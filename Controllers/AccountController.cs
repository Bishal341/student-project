using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using StudentProjectPapers.Models;
using StudentProjectPapers.Services;

namespace StudentProjectPapers.Controllers {
    [AutoValidateAntiforgeryToken]
    public class AccountController : Controller {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailService _emailService;
        private readonly ILogger<AccountController> _logger;

        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IEmailService emailService,
            ILogger<AccountController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailService = emailService;
            _logger = logger;
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                // User enumeration hardening: if the email is already registered we do
                // NOT create a second account, but we return the exact same success
                // response as a real registration so callers can never tell the email
                // exists. The existing user is notified instead.
                var existingUser = await _userManager.FindByEmailAsync(model.Email);
                if (existingUser != null)
                {
                    _logger.LogInformation("Registration attempt for already-registered email: {Email}", model.Email);

                    try
                    {
                        var alertBody = $@"
                            <h2>Someone tried to register with your email</h2>
                            <p>Hello {existingUser.FullName},</p>
                            <p>Someone attempted to create a new account on the Student Project Papers portal using the email address <strong>{model.Email}</strong>.</p>
                            <p>If this wasn't you, you can safely ignore this email. If you didn't register for this site, please contact the administrator.</p>";

                        await _emailService.SendEmailAsync(model.Email, "Registration attempt detected - Texas Library", alertBody);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to notify existing user of duplicate registration attempt: {Email}", model.Email);
                    }

                    TempData["Success"] = "Registration successful! Your account is pending admin approval.";
                    return RedirectToAction("Login");
                }

                var user = new ApplicationUser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    FullName = model.FullName,
                    Faculty = model.Faculty,
                    RegisteredDate = DateTime.Now,
                    IsApproved = false
                };

                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    await _userManager.AddToRoleAsync(user, "User");

                    // Forced password change: every newly created account must set a new
                    // password at first login (same flag the MustChangePasswordRedirectFilter
                    // and MobileApiController.Login read). Consistent with how the flag is
                    // written elsewhere: SetAuthenticationTokenAsync(user, "Default", "MustChangePassword", "true").
                    await _userManager.SetAuthenticationTokenAsync(user, "Default", "MustChangePassword", "true");

                    _logger.LogInformation("User registered: {Email}", user.Email);

                    var targetAdminEmail = GetAdminEmailForFaculty(user.Faculty);

                    var notifyBody = $@"
                        <div style='font-family:Arial,sans-serif;max-width:500px;margin:0 auto;'>
                            <h2 style='color:#3A2DC4;'>New Registration Pending Approval</h2>
                            <p><strong>Name:</strong> {user.FullName}</p>
                            <p><strong>Email:</strong> {user.Email}</p>
                            <p><strong>Faculty:</strong> {user.Faculty}</p>
                            <p>Please log in to the admin panel to review and approve this account.</p>
                        </div>";

                    await _emailService.SendEmailAsync(targetAdminEmail, "New User Pending Approval - Texas Library", notifyBody);

                    TempData["Success"] = "Registration successful! Your account is pending admin approval.";
                    return RedirectToAction("Login");
                }

                // Race guard: if the email became taken between the lookup and CreateAsync,
                // still hide the account's existence behind the same generic success.
                var duplicateError = result.Errors.FirstOrDefault(e =>
                    e.Description.Contains("already taken", StringComparison.OrdinalIgnoreCase));
                if (duplicateError != null)
                {
                    _logger.LogInformation("Registration attempt for already-registered email (race): {Email}", model.Email);
                    TempData["Success"] = "Registration successful! Your account is pending admin approval.";
                    return RedirectToAction("Login");
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }
            return View(model);
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [EnableRateLimiting("webLogin")]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                // User enumeration hardening: every failure path shows the same generic
                // message, so a login response can never reveal whether an account exists,
                // is approved, is verified, or is locked out. The specific reason is logged
                // server-side only.
                if (user != null && !user.IsApproved)
                {
                    _logger.LogInformation("Login blocked for {Email}: account not approved", model.Email);
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return View(model);
                }

                if (user != null && !user.IsEmailVerified)
                {
                    bool isAdmin = await _userManager.IsInRoleAsync(user, "Admin")
                        || await _userManager.IsInRoleAsync(user, "Master_Admin");
                    if (!isAdmin)
                    {
                        _logger.LogInformation("Login blocked for {Email}: email not verified", model.Email);
                        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                        return View(model);
                    }
                }

                Microsoft.AspNetCore.Identity.SignInResult result;
                if (user != null)
                {
                    result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, lockoutOnFailure: true);
                    if (result.Succeeded)
                    {
                        if (model.RememberMe)
                        {
                            var props = new Microsoft.AspNetCore.Authentication.AuthenticationProperties
                            {
                                IsPersistent = true,
                                ExpiresUtc = DateTimeOffset.UtcNow.AddDays(14)
                            };
                            await _signInManager.SignInAsync(user, props);
                        }
                        else
                        {
                            // Explicit properties: IsPersistent = false means no Expires attribute
                            // is written to the Set-Cookie header, so the browser discards the cookie
                            // when the session ends (browser close). ExpiresUtc is intentionally
                            // omitted — the server-side ticket lifetime (ExpireTimeSpan = 8 h from
                            // Program.cs) still applies for server validation, but the browser is
                            // never told an absolute expiry, so it treats this as a session cookie.
                            await _signInManager.SignInAsync(user, new Microsoft.AspNetCore.Authentication.AuthenticationProperties
                            {
                                IsPersistent = false
                            });
                        }
                    }
                }
                else
                {
                    result = Microsoft.AspNetCore.Identity.SignInResult.Failed;
                }

                if (result.Succeeded)
                {
                    _logger.LogInformation("User logged in: {Email}", model.Email);

                    // Enforce the MustChangePassword flag: don't let the user proceed to
                    // their dashboard until they have set a new password. The ChangePassword
                    // action clears the flag on success.
                    if (await _userManager.GetAuthenticationTokenAsync(user!, "Default", "MustChangePassword") == "true")
                    {
                        TempData["MustChangePassword"] = "For security, please set a new password before continuing to your account.";
                        return RedirectToAction("ChangePassword");
                    }

                    bool isAnyAdmin = await _userManager.IsInRoleAsync(user!, "Admin")
                        || await _userManager.IsInRoleAsync(user!, "BIT_Admin")
                        || await _userManager.IsInRoleAsync(user!, "BBA_Admin")
                        || await _userManager.IsInRoleAsync(user!, "Master_Admin");

                    if (isAnyAdmin)
                    {
                        string dashboardAction = AdminController.GetDashboardActionForFaculty(user!.Faculty);
                        return RedirectToAction(dashboardAction, "Admin");
                    }

                    string userDashboard = user!.Faculty switch
                    {
                        "BIT" => "BitDashboard",
                        "BCS" => "BitDashboard",
                        "BBA" => "BbaDashboard",
                        "Master" => "MasterDashboard",
                        _ => "Index"
                    };
                    return RedirectToAction(userDashboard, "Home");
                }

                if (result.IsLockedOut)
                {
                    // Generic message: does not reveal whether the account exists or the
                    // password was wrong (consistent with the user-enumeration finding).
                    _logger.LogInformation("Login blocked for {Email}: account locked out", model.Email);
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return View(model);
                }

                _logger.LogInformation("Login failed for {Email}: invalid credentials", model.Email);
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            }
            return View(model);
        }


        [HttpGet]
        public async Task<IActionResult> VerifyEmail(string token, string email)
        {
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(email))
                return BadRequest();

            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
            {
                TempData["Error"] = "Invalid or expired verification link.";
                return RedirectToAction("Login");
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);

            if (result.Succeeded)
            {
                user.IsEmailVerified = true;
                user.EmailVerificationToken = null;
                user.OtpCode = null;
                user.OtpExpiry = null;
                await _userManager.UpdateAsync(user);

                TempData["Success"] = "Your email has been verified! You can now log in.";
                return RedirectToAction("Login");
            }

            TempData["Error"] = "Invalid or expired verification link.";
            return RedirectToAction("Login");
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
                return Redirect(returnUrl);
            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            _logger.LogInformation("User logged out.");
            return RedirectToAction("Index", "Home");
        }

        [Authorize]
        [HttpGet]
        public IActionResult ChangePassword()
        {
            return View();
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return RedirectToAction("Login");

            var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);

            if (result.Succeeded)
            {
                // A successful password change clears the MustChangePassword flag so the
                // user can access the rest of the site again.
                await _userManager.RemoveAuthenticationTokenAsync(user, "Default", "MustChangePassword");
                await _signInManager.RefreshSignInAsync(user);
                _logger.LogInformation("User changed their password: {Email}", user.Email);

                bool isAnyAdmin = await _userManager.IsInRoleAsync(user, "Admin")
                      || await _userManager.IsInRoleAsync(user, "BIT_Admin")
                      || await _userManager.IsInRoleAsync(user, "BBA_Admin")
                      || await _userManager.IsInRoleAsync(user, "Master_Admin");

                if (isAnyAdmin)
                {
                    string dashboardAction = AdminController.GetDashboardActionForFaculty(user.Faculty);
                    return RedirectToAction(dashboardAction, "Admin");
                }

                string userDashboard = user.Faculty switch
                {
                    "BIT" => "BitDashboard",
                    "BCS" => "BitDashboard",
                    "BBA" => "BbaDashboard",
                    "Master" => "MasterDashboard",
                    _ => "Index"
                };
                return RedirectToAction(userDashboard, "Home");
            }

            foreach (var error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);

            return View(model);
        }

        [HttpGet]
        public IActionResult ResetPassword(string token, string email)
        {
            if (token == null || email == null)
                return BadRequest();

            var model = new ResetPasswordViewModel { Token = token, Email = email, Password = string.Empty, ConfirmPassword = string.Empty };
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return RedirectToAction("ResetPasswordConfirmation");

            var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
            if (result.Succeeded)
            {
                user.IsEmailVerified = true;
                user.OtpCode = null;
                user.OtpExpiry = null;
                await _userManager.UpdateAsync(user);

                // A reset link is how an admin-forced password change is completed, so
                // clearing the flag here keeps login and MustChangePassword consistent.
                await _userManager.RemoveAuthenticationTokenAsync(user, "Default", "MustChangePassword");

                return RedirectToAction("ResetPasswordConfirmation");
            }

            foreach (var error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);

            return View(model);
        }

        [HttpGet]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        private string GetAdminEmailForFaculty(string faculty)
        {
            return faculty switch
            {
                "BIT" => "BIT_Admin@projectpapers.com",
                "BBA" => "BBA_Admin@projectpapers.com",
                "Master" => "Master_Admin@projectpapers.com",
                _ => "admin@projectpapers.com"
            };
        }
    }
}