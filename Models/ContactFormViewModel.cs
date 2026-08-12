using System.ComponentModel.DataAnnotations;

namespace StudentProjectPapers.Models {
    public class ContactFormViewModel {
        [Required(ErrorMessage = "Please enter your name.")]
        public required string Name { get; set; }

        [Required(ErrorMessage = "Please enter your email.")]
        [EmailAddress(ErrorMessage = "Please enter a valid email address.")]
        public required string Email { get; set; }

        [Required(ErrorMessage = "Please enter a subject.")]
        public required string Subject { get; set; }

        [Required(ErrorMessage = "Please enter a message.")]
        [DataType(DataType.MultilineText)]
        public required string Message { get; set; }

        public bool AgreePrivacy { get; set; }
    }
}