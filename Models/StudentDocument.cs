using System.ComponentModel.DataAnnotations;

namespace StudentProjectPapers.Models {
    public enum DocumentType {
        InternReport,
        AttendanceReport,
        Letter
    }

    public enum DocumentStatus {
        Pending,
        Verified,
        Rejected
    }

    public class StudentDocument {
        [Key]
        public int Id { get; set; }

        public string? UserId { get; set; }

        [Required]
        [Display(Name = "Student Name")]
        public required string StudentName { get; set; }

        [Required]
        [Display(Name = "LCID")]
        public required string LCID { get; set; }

        [Required]
        [Display(Name = "Title")]
        [StringLength(500)]
        public required string Title { get; set; }

        [Required]
        public DocumentType DocumentType { get; set; }

        [Display(Name = "Company / Organization")]
        public string? CompanyName { get; set; }

        [Display(Name = "Supervisor Name")]
        public string? SupervisorName { get; set; }

        [Display(Name = "Additional Info")]
        public string? ExtraInfo { get; set; }

        [Display(Name = "Description")]
        public string? Description { get; set; }

        [Display(Name = "Year")]
        public int Year { get; set; }

        [Required]
        public required string FilePath { get; set; }

        [Required]
        public required string OriginalFileName { get; set; }

        public DateTime UploadedDate { get; set; } = DateTime.Now;

        public DocumentStatus Status { get; set; } = DocumentStatus.Pending;

        public string? RejectionReason { get; set; }

        public DateTime? VerifiedDate { get; set; }
    }
}
