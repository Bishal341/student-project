using System.ComponentModel.DataAnnotations;

namespace StudentProjectPapers.Models
{
    public class StudentProject
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [Display(Name = "LCID")]
        public required string LCID { get; set; }

        [Required]
        [Display(Name = "Student Name")]
        public required string StudentName { get; set; }

        [Required]
        [Display(Name = "Submitted Date")]
        [DataType(DataType.Date)]
        public DateTime SubmittedDate { get; set; }

        [Required]
        [Display(Name = "Project Title")]
        public required string ProjectTitle { get; set; }

        [Display(Name = "Project Description")]
        [StringLength(10000)]
        public string Description { get; set; } = string.Empty;

        [Required]
        public required string FilePath { get; set; }

        [Required]
        public required string OriginalFileName { get; set; }

        public DateTime UploadedDate { get; set; }

        [Display(Name = "Supervisor Name")]
        public string SupervisorName { get; set; } = string.Empty;

        [Display(Name = "Department")]
        public string Department { get; set; } = string.Empty;

        [Display(Name = "Year")]
        public int Year { get; set; }

        public string? UserId { get; set; }
    }
}
