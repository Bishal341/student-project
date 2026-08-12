using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using StudentProjectPapers.Data;
using StudentProjectPapers.Helpers;
using StudentProjectPapers.Models;
using StudentProjectPapers.Services;

namespace StudentProjectPapers.Controllers
{
    public class MobileLoginRequest
    {
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    public class NotifyApprovalRequest
    {
        public string UserId { get; set; } = string.Empty;
    }

    public class NotifyPasswordResetRequest
    {
        public string UserId { get; set; } = string.Empty;
        public bool MustChangePassword { get; set; }
    }

    public class MobileChangePasswordRequest
    {
        public string Email { get; set; } = string.Empty;
        public string ResetToken { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
    }

    /// <summary>
    /// Lightweight JSON API consumed by the MAUI Virtual Library mobile app.
    /// Mobile app auth uses JWT bearer tokens issued by POST /api/mobile/auth/login.
    /// </summary>
    [ApiController]
    [Route("api/mobile")]
    public class MobileApiController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IWebHostEnvironment _env;
        private readonly ILogger<MobileApiController> _logger;
        private readonly IEmailService _emailService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _configuration;

        public MobileApiController(
            ApplicationDbContext context,
            IWebHostEnvironment env,
            ILogger<MobileApiController> logger,
            IEmailService emailService,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IConfiguration configuration)
        {
            _context = context;
            _env = env;
            _logger = logger;
            _emailService = emailService;
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        [HttpGet("health")]
        [AllowAnonymous]
        public IActionResult Health() => Ok(new { status = "ok", app = "Student Project Papers" });

        /// <summary>
        /// JWT login for the mobile app. Replaces the old "trust the client-supplied
        /// userId" pattern with real Identity password verification and a signed token.
        /// Mirrors AccountController.Login's approval / email-verification checks.
        /// Rate limited per IP (5 req / 5 min) and honors Identity lockout so repeated
        /// failed guesses are throttled both by IP and per-account.
        /// </summary>
        [HttpPost("auth/login")]
        [AllowAnonymous]
        [EnableRateLimiting("mobileLogin")]
        public async Task<IActionResult> Login([FromBody] MobileLoginRequest request)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
                return BadRequest(new { success = false, message = "Email and password are required." });

            var user = await _userManager.FindByEmailAsync(request.Email);

            if (user == null)
                return Unauthorized(new { success = false, message = "Invalid login attempt." });

            // Honoring Identity's lockout: do not process the password at all when the
            // account is already locked. 423 Locked tells the app the account is
            // temporarily unavailable rather than that the password was wrong.
            if (await _userManager.IsLockedOutAsync(user))
                return StatusCode(StatusCodes.Status423Locked, new { success = false, message = "Too many failed login attempts. Your account is temporarily locked. Please try again later." });

            if (!user.IsApproved)
            {
                _logger.LogInformation("Login failed for {Email}: account not approved", request.Email);
                return Unauthorized(new { success = false, message = "Invalid login attempt." });
            }

            if (!user.IsEmailVerified)
            {
                bool isAdmin = await _userManager.IsInRoleAsync(user, "Admin")
                    || await _userManager.IsInRoleAsync(user, "Master_Admin");
                if (!isAdmin)
                {
                    _logger.LogInformation("Login failed for {Email}: email not verified", request.Email);
                    return Unauthorized(new { success = false, message = "Invalid login attempt." });
                }
            }

            // CheckPasswordSignInAsync respects Identity lockout: a locked account short-circuits
            // before the password is verified, a wrong password increments AccessFailedCount
            // (locking the account after MaxFailedAccessAttempts), and a correct one resets it.
            var signInResult = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
            if (signInResult.IsLockedOut)
                return StatusCode(StatusCodes.Status423Locked, new { success = false, message = "Too many failed login attempts. Your account is temporarily locked. Please try again later." });
            if (!signInResult.Succeeded)
                return Unauthorized(new { success = false, message = "Invalid login attempt." });

            // Enforce the MustChangePassword flag: do not issue a normal success token.
            // Return a distinct payload the MAUI app can branch on, plus a single-use
            // reset token it can pass to auth/change-password so the user is forced
            // through the change-password flow before gaining access.
            if (await _userManager.GetAuthenticationTokenAsync(user, "Default", "MustChangePassword") == "true")
            {
                var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
                return Ok(new
                {
                    success = false,
                    mustChangePassword = true,
                    message = "You must set a new password before you can continue.",
                    email = user.Email,
                    resetToken
                });
            }

            var roles = (await _userManager.GetRolesAsync(user)).ToList();
            var token = GenerateJwtToken(user, roles);

            return Ok(new
            {
                success = true,
                token,
                user = new
                {
                    id = user.Id,
                    email = user.Email,
                    fullName = user.FullName,
                    faculty = user.Faculty,
                    roles
                }
            });
        }

        /// <summary>
        /// Completes the MustChangePassword flow for the MAUI app. The user sends the
        /// reset token returned by auth/login (when mustChangePassword is true) plus the
        /// new password; on success the flag is cleared so the next login succeeds.
        /// Uses the same Identity reset-token validation as the web Account flow.
        /// </summary>
        [HttpPost("auth/change-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ChangePassword([FromBody] MobileChangePasswordRequest request)
        {
            if (request == null
                || string.IsNullOrWhiteSpace(request.Email)
                || string.IsNullOrWhiteSpace(request.ResetToken)
                || string.IsNullOrWhiteSpace(request.NewPassword))
            {
                return BadRequest(new { success = false, message = "Email, reset token and new password are required." });
            }

            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
                return BadRequest(new { success = false, message = "Invalid request." });

            var result = await _userManager.ResetPasswordAsync(user, request.ResetToken, request.NewPassword);
            if (!result.Succeeded)
            {
                var errors = string.Join(" ", result.Errors.Select(e => e.Description));
                return BadRequest(new { success = false, message = string.IsNullOrWhiteSpace(errors) ? "Invalid or expired reset token." : errors });
            }

            await _userManager.RemoveAuthenticationTokenAsync(user, "Default", "MustChangePassword");

            return Ok(new { success = true, message = "Password updated. You can now log in with your new password." });
        }

        private string GenerateJwtToken(ApplicationUser user, IList<string> roles)
        {
            var secretKey = _configuration["Jwt:SecretKey"] ?? string.Empty;
            var issuer = _configuration["Jwt:Issuer"] ?? "StudentProjectPapers";
            var audience = _configuration["Jwt:Audience"] ?? "StudentProjectPapersMobileApp";
            int.TryParse(_configuration["Jwt:ExpiryMinutes"], out int expiryMinutes);
            if (expiryMinutes <= 0) expiryMinutes = 120;

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("fullName", user.FullName),
                new Claim("faculty", user.Faculty ?? string.Empty)
            };

            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddMinutes(expiryMinutes),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        /// <summary>
        /// Resolves the caller's identity from the JWT "sub" claim, falling back to the
        /// inbound-mapped NameIdentifier claim in case claim mapping is disabled.
        /// Tokens are issued with the sub claim set to the user id in GenerateJwtToken.
        /// Client-supplied user ids are never used for identity decisions.
        /// </summary>
        private async Task<ApplicationUser?> GetCurrentUserAsync()
        {
            var sub = User.FindFirst(JwtRegisteredClaimNames.Sub)
                      ?? User.FindFirst(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(sub?.Value))
                return null;

            return await _context.Users.FirstOrDefaultAsync(u => u.Id == sub.Value);
        }

        /// <summary>
        /// Delegates to FacultyHelper.GetManagedFaculties for faculty access rules.
        /// </summary>
        private static string[] GetManagedFaculties(string? faculty) => FacultyHelper.GetManagedFaculties(faculty);

        /// <summary>
        /// True only when the JWT-derived caller is an admin (Admin or Master_Admin) and
        /// the target user belongs to a faculty the caller manages. Prevents a faculty
        /// admin from acting on users outside their scope and non-admins from acting on
        /// any other user.
        /// </summary>
        private async Task<bool> CanAdminActOnUserAsync(ApplicationUser target)
        {
            var caller = await GetCurrentUserAsync();
            if (caller == null)
                return false;

            bool isAdmin = await _userManager.IsInRoleAsync(caller, "Admin")
                        || await _userManager.IsInRoleAsync(caller, "Master_Admin");
            if (!isAdmin)
                return false;

            if (string.IsNullOrEmpty(caller.Faculty) || caller.Faculty == "All")
                return true;

            return GetManagedFaculties(caller.Faculty).Contains(target.Faculty);
        }

        /// <summary>
        /// Handle contact form submissions from the MAUI mobile app.
        /// Sends the same email as the web Contact POST in HomeController.
        /// </summary>
        [HttpPost("contact")]
        [EnableRateLimiting("mobileContact")]
        public async Task<IActionResult> Contact([FromBody] ContactFormViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(new { success = false, message = "Please fill in all required fields." });

            var body = $@"
                <h3>New Contact Form Submission</h3>
                <p><strong>Name:</strong> {WebUtility.HtmlEncode(model.Name)}</p>
                <p><strong>Email:</strong> {WebUtility.HtmlEncode(model.Email)}</p>
                <p><strong>Subject:</strong> {WebUtility.HtmlEncode(model.Subject)}</p>
                <p><strong>Message:</strong></p>
                <p>{WebUtility.HtmlEncode(model.Message)}</p>";

            await _emailService.SendEmailAsync("texasalumnipapers@gmail.com", $"Contact Form: {model.Subject}", body);

            return Ok(new { success = true, message = "Thanks for reaching out! We'll get back to you soon." });
        }

        /// <summary>
        /// Sends the approval notification email after an admin approves a user
        /// (approval itself is written directly to the DB by the MAUI app).
        /// </summary>
        [HttpPost("notify/approval")]
        [Authorize(AuthenticationSchemes = "Bearer")]
        public async Task<IActionResult> NotifyApproval([FromBody] NotifyApprovalRequest request)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == request.UserId);
            if (user == null)
                return NotFound(new { success = false, message = "User not found." });

            // Cross-user action: only a JWT-authenticated admin whose faculty scope
            // covers the target user may send an approval notification.
            if (!await CanAdminActOnUserAsync(user))
                return Forbid();

            var body = $@"
                <h3>Your account has been approved</h3>
                <p>Hi {WebUtility.HtmlEncode(user.FullName)},</p>
                <p>Your account has been approved. You can now log in and start using the platform.</p>";

            try
            {
                await _emailService.SendEmailAsync(user.Email, "Your account has been approved", body);
                return Ok(new { success = true });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send approval email to {Email}", user.Email);
                return StatusCode(500, new { success = false, message = "Approved, but the notification email failed to send." });
            }
        }

        /// <summary>
        /// Sends a password-reset notification email after an admin resets a user's
        /// password (the reset itself is written directly to the DB by the MAUI app).
        /// Deliberately does NOT accept or email the plaintext password.
        /// </summary>
        [HttpPost("notify/password-reset")]
        [Authorize(AuthenticationSchemes = "Bearer")]
        public async Task<IActionResult> NotifyPasswordReset([FromBody] NotifyPasswordResetRequest request)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == request.UserId);
            if (user == null)
                return NotFound(new { success = false, message = "User not found." });

            // Cross-user action: only a JWT-authenticated admin whose faculty scope
            // covers the target user may send a password-reset notification.
            if (!await CanAdminActOnUserAsync(user))
                return Forbid();

            var changeNote = request.MustChangePassword
                ? "<p>You will be asked to set a new password the next time you log in.</p>"
                : string.Empty;

            var body = $@"
                <h3>Your password has been reset</h3>
                <p>Hi {WebUtility.HtmlEncode(user.FullName)},</p>
                <p>An administrator has reset your password. If you did not expect this, please contact us immediately.</p>
                {changeNote}";

            try
            {
                await _emailService.SendEmailAsync(user.Email, "Your password has been reset", body);
                return Ok(new { success = true });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send password-reset email to {Email}", user.Email);
                return StatusCode(500, new { success = false, message = "Password reset, but the notification email failed to send." });
            }
        }

        /// <summary>
        /// Upload an intern/attendance/letter document from the mobile app.
        /// Saves into private-uploads/documents (ContentRootPath-relative, OUTSIDE wwwroot)
        /// so private documents are never publicly servable via the static-file middleware.
        /// </summary>
        [HttpPost("documents/upload")]
        [Authorize(AuthenticationSchemes = "Bearer")]
        [RequestSizeLimit(10 * 1024 * 1024)]
        public async Task<IActionResult> UploadDocument(
            [FromForm] DocumentType documentType,
            [FromForm] string studentName,
            [FromForm] string lcid,
            [FromForm] string title,
            [FromForm] string? companyName,
            [FromForm] int year,
            [FromForm] string? supervisorName,
            [FromForm] string? description,
            [FromForm] string? extraInfo,
            [FromForm] IFormFile documentFile)
        {
            // Identity comes from the authenticated JWT (sub claim), never from
            // client-supplied input. A supplied userId in the form is ignored.
            var user = await GetCurrentUserAsync();
            if (user == null || !user.IsApproved)
                return Unauthorized(new { success = false, message = "User not found or not approved." });

            if (documentFile == null || documentFile.Length == 0)
                return BadRequest(new { success = false, message = "Please select a file to upload." });

            var allowed = new[] { ".pdf", ".jpg", ".jpeg", ".png" };
            var ext = Path.GetExtension(documentFile.FileName).ToLowerInvariant();
            if (!allowed.Contains(ext))
                return BadRequest(new { success = false, message = "Only PDF or image files (jpg, jpeg, png) are allowed." });

            if (documentFile.Length > 10 * 1024 * 1024)
                return BadRequest(new { success = false, message = "File size must not exceed 10MB." });

            // Magic-byte verification: never trust the filename or browser-supplied
            // Content-Type alone. The file's actual header must match the claimed
            // extension (e.g. a real PDF begins with "%PDF-") BEFORE it is written.
            if (!IsAllowedDocumentContent(documentFile, ext, out var contentError))
                return BadRequest(new { success = false, message = contentError });

            try
            {
                var uploadsFolder = Path.Combine(_env.ContentRootPath, "private-uploads", "documents");
                Directory.CreateDirectory(uploadsFolder);

                var uniqueFileName = $"{Guid.NewGuid()}_{Path.GetFileName(documentFile.FileName)}";
                var filePath = Path.Combine(uploadsFolder, uniqueFileName);

                await using (var stream = System.IO.File.Create(filePath))
                {
                    await documentFile.CopyToAsync(stream);
                }

                var document = new StudentDocument
                {
                    UserId = user.Id,
                    StudentName = studentName,
                    LCID = lcid,
                    Title = title,
                    DocumentType = documentType,
                    CompanyName = companyName,
                    SupervisorName = supervisorName,
                    ExtraInfo = extraInfo,
                    Description = description,
                    Year = year,
                    // Store just the filename (not a public URL). Consumers reconstruct the
                    // full path from ContentRootPath (private-uploads/documents) at read time.
                    FilePath = uniqueFileName,
                    OriginalFileName = documentFile.FileName,
                    UploadedDate = DateTime.Now,
                    Status = DocumentStatus.Pending
                };

                _context.StudentDocuments.Add(document);
                await _context.SaveChangesAsync();

                return Ok(new
                {
                    success = true,
                    message = "Document submitted successfully! It will be reviewed by admin.",
                    documentId = document.Id,
                    filePath = document.FilePath
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Mobile document upload failed");
                return StatusCode(500, new { success = false, message = "Upload failed. Please try again." });
            }
        }

        /// <summary>
        /// Download a project PDF (faculty-scoped).
        /// </summary>
        [HttpGet("projects/{id:int}/download")]
        [Authorize(AuthenticationSchemes = "Bearer")]
        public async Task<IActionResult> DownloadProject(int id)
        {
            var project = await _context.StudentProjects.FindAsync(id);
            if (project == null) return NotFound();

            // Identity comes from the authenticated JWT (sub claim), never from
            // client-supplied input. A supplied userId in the query string is ignored.
            var user = await GetCurrentUserAsync();
            if (user == null || !user.IsApproved)
                return Unauthorized();

            if (!string.IsNullOrEmpty(user.Faculty) &&
                user.Faculty != "All" &&
                !string.Equals(project.Department, user.Faculty, StringComparison.OrdinalIgnoreCase))
            {
                return Forbid();
            }

            // Ownership gate (IDOR guard): a project linked to a specific user
            // (student-uploaded row) may only be downloaded by that user or an Admin.
            // Admin-published projects (UserId empty) remain faculty-scoped above.
            if (!string.IsNullOrEmpty(project.UserId) &&
                project.UserId != user.Id &&
                !User.IsInRole("Admin"))
            {
                return Forbid();
            }

            var filePath = Path.Combine(_env.ContentRootPath, "private-uploads", "projects",
                ResolveProjectFileName(project.FilePath));
            if (!System.IO.File.Exists(filePath))
                return NotFound(new { message = "File not found on server." });

            var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            return File(stream, "application/pdf", project.OriginalFileName);
        }

        /// <summary>
        /// Magic-byte validation for document uploads (PDF / JPG / PNG). The claimed
        /// extension must match the file's actual signature, rejecting renamed executables
        /// or other non-matching content before anything is written to disk.
        /// </summary>
        private static bool IsAllowedDocumentContent(IFormFile file, string extension, out string error)
        {
            using var stream = file.OpenReadStream();
            var header = new byte[8];
            var read = stream.Read(header, 0, header.Length);
            if (read < 4)
            {
                error = "The uploaded file is empty or unreadable.";
                return false;
            }

            bool valid = extension switch
            {
                ".pdf" => read >= 5 &&
                          header[0] == 0x25 && header[1] == 0x50 && header[2] == 0x44 &&
                          header[3] == 0x46 && header[4] == 0x2D, // %PDF-
                ".jpg" or ".jpeg" => read >= 3 &&
                          header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF, // JFIF
                ".png" => read >= 8 &&
                          header[0] == 0x89 && header[1] == 0x50 && header[2] == 0x4E &&
                          header[3] == 0x47 && header[4] == 0x0D && header[5] == 0x0A &&
                          header[6] == 0x1A && header[7] == 0x0A, // PNG signature
                _ => false
            };

            if (!valid)
            {
                error = "The uploaded file's content does not match its file type. Only valid PDF or image files are allowed.";
                return false;
            }

            error = null;
            return true;
        }

        /// <summary>
        /// New rows store just the filename; legacy rows stored "/uploads/&lt;file&gt;".
        /// Both resolve to private-uploads/projects (ContentRootPath-relative, OUTSIDE
        /// wwwroot, never served by the static-file middleware).
        /// </summary>
        private static string ResolveProjectFileName(string? filePath)
        {
            var storedPath = filePath ?? string.Empty;
            return storedPath.StartsWith("/uploads/", StringComparison.OrdinalIgnoreCase)
                ? storedPath.Substring("/uploads/".Length).TrimStart('/')
                : storedPath.TrimStart('/');
        }
    }
}