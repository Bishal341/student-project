using System.ComponentModel.DataAnnotations;

namespace StudentProjectPapers.Models
{
    public class AdminResetPasswordViewModel
    {
        public required string UserId { get; set; }
        public required string UserEmail { get; set; }
        public required string UserName { get; set; }

        [Display(Name = "Send Email Notification")]
        public bool SendEmailNotification { get; set; } = true;

        [Display(Name = "User Must Change Password at Next Login")]
        public bool MustChangePassword { get; set; } = true;
    }
}
