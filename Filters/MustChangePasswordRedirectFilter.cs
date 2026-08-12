using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using StudentProjectPapers.Models;

namespace StudentProjectPapers.Filters
{
    /// <summary>
    /// Web-side enforcement of the MustChangePassword flag (security audit Fix 2).
    /// Any cookie-authenticated user whose flag is still set is sent to
    /// Account/ChangePassword and kept off every other page until they set a new
    /// password. The Account login/password actions are exempt so the user can always
    /// reach and complete the change flow. JWT/"Bearer" requests (the mobile API) are
    /// ignored — MobileApiController handles that flow with its own response.
    /// </summary>
    public class MustChangePasswordRedirectFilter : IAsyncActionFilter
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public MustChangePasswordRedirectFilter(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            if (await RequiresPasswordChangeAsync(context))
            {
                context.Result = new RedirectToActionResult("ChangePassword", "Account", null);
                return;
            }

            await next();
        }

        private async Task<bool> RequiresPasswordChangeAsync(ActionExecutingContext context)
        {
            var identity = context.HttpContext.User.Identity;
            if (identity == null || !identity.IsAuthenticated)
                return false;

            // Only the web cookie scheme is funnelled through the change-password page.
            // JWT (mobile API) requests must keep returning JSON, never redirects.
            var path = context.HttpContext.Request.Path.Value ?? string.Empty;
            if (path.StartsWith("/api/", StringComparison.OrdinalIgnoreCase))
                return false;

            if (!string.Equals(identity.AuthenticationType, IdentityConstants.ApplicationScheme, StringComparison.Ordinal))
                return false;

            var action = context.ActionDescriptor as ControllerActionDescriptor;
            if (action == null)
                return false;

            // Actions the user must be able to reach even while the flag is set.
            if (string.Equals(action.ControllerName, "Account", StringComparison.OrdinalIgnoreCase))
            {
                var exempt = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "Login", "Register", "Logout",
                    "ChangePassword", "ResetPassword", "ResetPasswordConfirmation", "VerifyEmail"
                };
                if (exempt.Contains(action.ActionName))
                    return false;
            }

            var user = await _userManager.GetUserAsync(context.HttpContext.User);
            if (user == null)
                return false;

            return await _userManager.GetAuthenticationTokenAsync(user, "Default", "MustChangePassword") == "true";
        }
    }
}
