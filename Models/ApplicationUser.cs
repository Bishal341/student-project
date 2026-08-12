using Microsoft.AspNetCore.Identity;

namespace StudentProjectPapers.Models {
    public class ApplicationUser : IdentityUser {
        public required string FullName { get; set; }
        public DateTime RegisteredDate { get; set; }
        public bool IsApproved { get; set; }
        public DateTime? ApprovedDate { get; set; }
        public string? OtpCode { get; set; }
        public DateTime? OtpExpiry { get; set; }
        public bool IsEmailVerified { get; set; }
        public string? ProfilePicture { get; set; }

        public string? EmailVerificationToken { get; set; }

        public required string Faculty { get; set; }
    }
}