using System;
using System.ComponentModel.DataAnnotations;

namespace StudentProjectPapers.Models
{
    public class UserManagementViewModel
    {
        public string Id { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string PhoneNumber { get; set; } = string.Empty;
        public DateTime RegisteredDate { get; set; }
        public DateTime? ApprovedDate { get; set; }
        public bool IsApproved { get; set; }
        public string Role { get; set; } = string.Empty;
        public string PasswordStatus { get; set; } = string.Empty;
        public DateTime? LastLoginDate { get; set; }
        public bool MustChangePassword { get; set; }
    }

    public class UserDetailsViewModel
    {
        public string Id { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string PhoneNumber { get; set; } = string.Empty;
        public DateTime RegisteredDate { get; set; }
        public DateTime? ApprovedDate { get; set; }
        public bool IsApproved { get; set; }
        public string Role { get; set; } = string.Empty;
        public bool EmailConfirmed { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        public bool TwoFactorEnabled { get; set; }
        public int AccessFailedCount { get; set; }
        public DateTimeOffset? LockoutEnd { get; set; }
        public string PasswordStatus { get; set; } = string.Empty;
        public bool MustChangePassword { get; set; }
    }
}