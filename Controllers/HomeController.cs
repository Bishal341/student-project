using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SixLabors.ImageSharp;
using StudentProjectPapers.Data;
using StudentProjectPapers.Helpers;
using StudentProjectPapers.Models;
using StudentProjectPapers.Services;
using System.Diagnostics;
using System.Net;

namespace StudentProjectPapers.Controllers {
    [AutoValidateAntiforgeryToken]
    public class HomeController : Controller {
        private readonly ILogger<HomeController> _logger;
        private readonly ApplicationDbContext _context;
        private readonly IEmailService _emailService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IWebHostEnvironment _webHostEnvironment;

        public HomeController(ILogger<HomeController> logger, ApplicationDbContext context,
            IEmailService emailService, UserManager<ApplicationUser> userManager,
            IWebHostEnvironment webHostEnvironment)
        {
            _logger = logger;
            _context = context;
            _emailService = emailService;
            _userManager = userManager;
            _webHostEnvironment = webHostEnvironment;
        }

        public async Task<IActionResult> Index()
        {

            if (User.Identity != null && User.Identity.IsAuthenticated &&
                (User.IsInRole("Admin") || User.IsInRole("BIT_Admin") || User.IsInRole("BBA_Admin") || User.IsInRole("Master_Admin")))
            {
                var currentUser = await _userManager.GetUserAsync(User);
                var dashboardAction = AdminController.GetDashboardActionForFaculty(currentUser?.Faculty);
                return RedirectToAction(dashboardAction, "Admin");
            }

            var recentProjects = await _context.StudentProjects
                 .OrderByDescending(p => p.UploadedDate)
                 .Take(10)
                 .ToListAsync();
            return View(recentProjects);
        }

        [HttpGet]
        public IActionResult Contact()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Contact(ContactFormViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var body = $@"
                <h3>New Contact Form Submission</h3>
                <p><strong>Name:</strong> {WebUtility.HtmlEncode(model.Name)}</p>
                <p><strong>Email:</strong> {WebUtility.HtmlEncode(model.Email)}</p>
                <p><strong>Subject:</strong> {WebUtility.HtmlEncode(model.Subject)}</p>
                <p><strong>Message:</strong></p>
                <p>{WebUtility.HtmlEncode(model.Message)}</p>";

            await _emailService.SendEmailAsync("texasalumnipapers@gmail.com", $"Contact Form: {model.Subject}", body);

            TempData["ContactSuccess"] = "Thanks for reaching out! We'll get back to you soon.";
            return RedirectToAction("Contact");
        }

        [Authorize]
        public async Task<IActionResult> BcsDashboard()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user?.Faculty != "BCS") return RedirectToAction("Index");
            var faculties = FacultyHelper.GetManagedFaculties(user.Faculty);
            var recentProjects = await _context.StudentProjects
                .Where(p => faculties.Contains(p.Department))
                .OrderByDescending(p => p.UploadedDate)
                .Take(6).ToListAsync();
            return View("Index", recentProjects);
        }

        [Authorize]
        public async Task<IActionResult> BitDashboard()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user?.Faculty != "BIT") return RedirectToAction("Index");
            var faculties = FacultyHelper.GetManagedFaculties(user.Faculty);
            var recentProjects = await _context.StudentProjects
                .Where(p => faculties.Contains(p.Department))
                .OrderByDescending(p => p.UploadedDate)
                .Take(6).ToListAsync();
            return View("Index", recentProjects);
        }

        [Authorize]
        public async Task<IActionResult> BbaDashboard()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user?.Faculty != "BBA") return RedirectToAction("Index");
            var recentProjects = await _context.StudentProjects
                .Where(p => p.Department == "BBA")
                .OrderByDescending(p => p.UploadedDate)
                .Take(6).ToListAsync();
            return View("Index", recentProjects);
        }

        [Authorize]
        public async Task<IActionResult> MasterDashboard()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user?.Faculty != "Master") return RedirectToAction("Index");
            var recentProjects = await _context.StudentProjects
                .Where(p => p.Department == "Master")
                .OrderByDescending(p => p.UploadedDate)
                .Take(6).ToListAsync();
            return View("Index", recentProjects);
        }

        [Authorize]
        public async Task<IActionResult> BrowseProjects(string searchString, string department, int? year)
        {
            var user = await _userManager.GetUserAsync(User);
            var userFaculty = user?.Faculty;

            var projects = _context.StudentProjects.AsQueryable();

            // BIT and BCS students share one project pool — uses FacultyHelper.GetManagedFaculties.
            // null facultiesToShow means super-admin / no-faculty-scope: sees everything.
            var facultiesToShow = string.IsNullOrEmpty(userFaculty) ? null : FacultyHelper.GetManagedFaculties(userFaculty);

            if (facultiesToShow != null)
            {
                projects = projects.Where(p => facultiesToShow.Contains(p.Department));
            }

            if (!string.IsNullOrEmpty(searchString))
            {
                projects = projects.Where(p => p.ProjectTitle.Contains(searchString) ||
                                              p.StudentName.Contains(searchString) ||
                                              p.LCID.Contains(searchString));
            }

            if (!string.IsNullOrEmpty(department))
            {
                projects = projects.Where(p => p.Department == department);
            }

            if (year.HasValue)
            {
                projects = projects.Where(p => p.Year == year.Value);
            }

            var departmentsQuery = _context.StudentProjects.AsQueryable();
            var yearsQuery = _context.StudentProjects.AsQueryable();
            if (facultiesToShow != null)
            {
                departmentsQuery = departmentsQuery.Where(p => facultiesToShow.Contains(p.Department));
                yearsQuery = yearsQuery.Where(p => facultiesToShow.Contains(p.Department));
            }

            ViewBag.Departments = await departmentsQuery
                .Select(p => p.Department).Distinct().ToListAsync();
            ViewBag.Years = await yearsQuery
                .Select(p => p.Year).Distinct().OrderByDescending(y => y).ToListAsync();

            return View(await projects.ToListAsync());
        }

        [Authorize]
        public async Task<IActionResult> DownloadProject(int id)
        {
            var project = await _context.StudentProjects.FindAsync(id);
            if (project == null)
                return NotFound();

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return Forbid();

            // Faculty scope: a non-admin can only download projects from their own
            // faculty. Admin-published projects (UserId empty) carry no per-user
            // ownership, so this scope check is the whole authorization for them.
            if (!string.IsNullOrEmpty(user.Faculty) && project.Department != user.Faculty)
                return Forbid();

            // Ownership gate (IDOR guard): a project linked to a specific user
            // (student-uploaded row) may only be downloaded by that user or an Admin.
            if (!string.IsNullOrEmpty(project.UserId) && project.UserId != user.Id && !User.IsInRole("Admin"))
                return Forbid();

            var filePath = ResolvePrivateProjectPath(project);
            if (!System.IO.File.Exists(filePath))
                return NotFound();

            return PhysicalFile(filePath, "application/pdf", project.OriginalFileName);
        }

        [Authorize]
        public IActionResult InternReport()
        {
            return View();
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UploadDocument(
            DocumentType documentType, string studentName, string lcid, string title,
            string companyName, int year, string supervisorName,
            string description, string extraInfo, IFormFile documentFile)
        {
            string redirectAction = "InternReport";

            if (documentFile == null || documentFile.Length == 0)
            {
                TempData["Error"] = "Please select a file to upload.";
                return RedirectToAction(redirectAction);
            }

            var allowedExtensions = new[] { ".pdf", ".jpg", ".jpeg", ".png" };
            var ext = Path.GetExtension(documentFile.FileName).ToLower();
            if (!allowedExtensions.Contains(ext))
            {
                TempData["Error"] = "Only PDF or image files (jpg, jpeg, png) are allowed.";
                return RedirectToAction(redirectAction);
            }

            if (documentFile.Length > 10 * 1024 * 1024)
            {
                TempData["Error"] = "File size must not exceed 10MB.";
                return RedirectToAction(redirectAction);
            }

            // Magic-byte verification: never trust the filename or browser-supplied
            // Content-Type alone. The file's actual header must match the claimed
            // extension (e.g. a real PDF begins with "%PDF-") BEFORE it is written.
            if (!IsAllowedDocumentContent(documentFile, ext, out var contentError))
            {
                TempData["Error"] = contentError;
                return RedirectToAction(redirectAction);
            }

            try
            {
                // PRIVATE storage: ContentRootPath keeps these files OUTSIDE wwwroot so
                // they can never be served by the static-file middleware. Do NOT move
                // this back under WebRootPath.
                var uploadsFolder = Path.Combine(_webHostEnvironment.ContentRootPath, "private-uploads", "documents");
                if (!Directory.Exists(uploadsFolder))
                    Directory.CreateDirectory(uploadsFolder);

                var uniqueFileName = $"{Guid.NewGuid()}_{Path.GetFileName(documentFile.FileName)}";
                var filePath = Path.Combine(uploadsFolder, uniqueFileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await documentFile.CopyToAsync(stream);
                }

                var currentUser = await _userManager.GetUserAsync(User);
                var document = new StudentDocument
                {
                    UserId = currentUser?.Id,
                    StudentName = studentName,
                    LCID = lcid,
                    Title = title,
                    DocumentType = documentType,
                    CompanyName = companyName,
                    SupervisorName = supervisorName,
                    ExtraInfo = extraInfo,
                    Description = description,
                    Year = year,
                    // Store just the filename (not a public URL). ViewDocument/DownloadDocument
                    // reconstruct the full path from ContentRootPath at read time.
                    FilePath = uniqueFileName,
                    OriginalFileName = documentFile.FileName,
                    UploadedDate = DateTime.Now,
                    Status = DocumentStatus.Pending
                };

                _context.StudentDocuments.Add(document);
                await _context.SaveChangesAsync();

                TempData["Success"] = "Your document has been submitted successfully! It will be reviewed by admin.";
            }
            /* catch (Exception ex)
             {
                 _logger.LogError(ex, "Error uploading document");
                 var innerMsg = ex.InnerException != null ? ex.InnerException.Message : ex.Message;
                 TempData["Error"] = "ERROR: " + innerMsg;
             }*/

            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading document");
                TempData["Error"] = "An error occurred while uploading. Please try again.";
            }

            return RedirectToAction(redirectAction);
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

        [Authorize]
        public async Task<IActionResult> ViewDocument(int id)
        {
            var document = await _context.StudentDocuments.FindAsync(id);
            if (document == null)
                return NotFound();

            if (!await CanAccessDocumentAsync(document))
                return Forbid();

            var filePath = ResolvePrivateDocumentPath(document);
            if (!System.IO.File.Exists(filePath))
                return NotFound();

            var ext = Path.GetExtension(filePath).ToLower();
            var contentType = ext switch
            {
                ".pdf" => "application/pdf",
                ".jpg" or ".jpeg" => "image/jpeg",
                ".png" => "image/png",
                _ => "application/octet-stream"
            };

            return PhysicalFile(filePath, contentType);
        }

        [Authorize]
        public async Task<IActionResult> DownloadDocument(int id)
        {
            var document = await _context.StudentDocuments.FindAsync(id);
            if (document == null)
                return NotFound();

            if (!await CanAccessDocumentAsync(document))
                return Forbid();

            var filePath = ResolvePrivateDocumentPath(document);
            if (!System.IO.File.Exists(filePath))
                return NotFound();

            return PhysicalFile(filePath, "application/octet-stream", document.OriginalFileName);
        }

        /// <summary>
        /// Resolves a private student document to its on-disk path.
        /// New rows store just the filename; legacy rows stored "/uploads/documents/&lt;file&gt;".
        /// Legacy rows are resolved under WebRootPath until the one-time migration
        /// (Admin/MigratePrivateDocuments) moves the files and rewrites FilePath.
        /// </summary>
        private string ResolvePrivateDocumentPath(StudentDocument document)
        {
            var storedPath = document.FilePath ?? string.Empty;

            if (storedPath.StartsWith("/uploads/documents/", StringComparison.OrdinalIgnoreCase))
            {
                return Path.Combine(_webHostEnvironment.WebRootPath, storedPath.TrimStart('/'));
            }

            return Path.Combine(_webHostEnvironment.ContentRootPath, "private-uploads", "documents",
                storedPath.TrimStart('/'));
        }

        /// <summary>
        /// Resolves a project PDF to its on-disk path.
        /// New rows store just the filename; legacy rows stored "/uploads/&lt;file&gt;".
        /// Both resolve to private-uploads/projects (ContentRootPath-relative, OUTSIDE
        /// wwwroot, never served by the static-file middleware).
        /// </summary>
        private string ResolvePrivateProjectPath(StudentProject project)
        {
            var storedPath = project.FilePath ?? string.Empty;
            var fileName = storedPath.StartsWith("/uploads/", StringComparison.OrdinalIgnoreCase)
                ? storedPath.Substring("/uploads/".Length).TrimStart('/')
                : storedPath.TrimStart('/');
            return Path.Combine(_webHostEnvironment.ContentRootPath, "private-uploads", "projects", fileName);
        }

        /// <summary>
        /// Authorization for private documents (IDOR guard, mirrors AdminController's
        /// faculty scoping). Allows: the document's owner, super admins (empty/"All"
        /// Faculty), and faculty admins for documents whose owner belongs to their
        /// managed faculties (BIT manages BIT + BCS). Everyone else is denied.
        /// </summary>
        private async Task<bool> CanAccessDocumentAsync(StudentDocument document)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return false;

            if (document.UserId == user.Id)
                return true;

            var isAdmin =
                await _userManager.IsInRoleAsync(user, "Admin") ||
                await _userManager.IsInRoleAsync(user, "BIT_Admin") ||
                await _userManager.IsInRoleAsync(user, "BBA_Admin") ||
                await _userManager.IsInRoleAsync(user, "Master_Admin");
            if (!isAdmin)
                return false;

            if (string.IsNullOrEmpty(user.Faculty) || user.Faculty == "All")
                return true;

            var managedFaculties = FacultyHelper.GetManagedFaculties(user.Faculty);

            var owner = await _userManager.FindByIdAsync(document.UserId);
            return owner != null && managedFaculties.Contains(owner.Faculty);
        }

        [Authorize]
        public async Task<IActionResult> SearchProjects(string query)
        {
            if (string.IsNullOrEmpty(query) || query.Length < 2)
                return Json(new List<object>());

            var user = await _userManager.GetUserAsync(User);
            var userFaculty = user?.Faculty;

            var searchQuery = _context.StudentProjects.AsQueryable();
            if (!string.IsNullOrEmpty(userFaculty))
                searchQuery = searchQuery.Where(p => p.Department == userFaculty);

            var results = await searchQuery
                .Where(p => p.ProjectTitle.Contains(query) ||
                            p.StudentName.Contains(query) ||
                            p.LCID.Contains(query) ||
                            p.Department.Contains(query))
                .OrderByDescending(p => p.UploadedDate)
                .Take(6)
                .Select(p => new {
                    p.Id,
                    p.ProjectTitle,
                    p.StudentName,
                    p.Department,
                    p.Year
                })
                .ToListAsync();

            return Json(results);
        }

        [Authorize]
        public async Task<IActionResult> MyProfile()
        {
            var user = await _userManager.GetUserAsync(User);
            return View(user);
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UploadProfilePicture(IFormFile profileImage)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return NotFound();

            if (profileImage == null || profileImage.Length == 0)
            {
                TempData["Error"] = "Please select an image.";
                return RedirectToAction("MyProfile");
            }

            var allowed = new[] { ".jpg", ".jpeg", ".png", ".gif", ".webp" };
            var ext = Path.GetExtension(profileImage.FileName).ToLower();
            if (!allowed.Contains(ext))
            {
                TempData["Error"] = "Only image files are allowed (jpg, png, gif, webp).";
                return RedirectToAction("MyProfile");
            }

            if (profileImage.Length > 2 * 1024 * 1024)
            {
                TempData["Error"] = "Image must be under 2MB.";
                return RedirectToAction("MyProfile");
            }

            // Re-encode with ImageSharp: anything that does not decode as a valid image is
            // rejected here (Image.LoadAsync throws on non-image bytes), and re-encoding
            // strips embedded metadata/EXIF. Output is normalized to JPEG for storage
            // regardless of the original extension (jpg/png/gif/webp).
            byte[] imageBytes;
            try
            {
                using var inputStream = profileImage.OpenReadStream();
                using var image = await Image.LoadAsync(inputStream);
                using var outputStream = new MemoryStream();
                await image.SaveAsJpegAsync(outputStream);
                imageBytes = outputStream.ToArray();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Profile picture rejected: not a decodable image");
                TempData["Error"] = "The uploaded file is not a valid image.";
                return RedirectToAction("MyProfile");
            }

            var folder = Path.Combine(_webHostEnvironment.WebRootPath, "profile-pictures");
            if (!Directory.Exists(folder))
                Directory.CreateDirectory(folder);

            if (!string.IsNullOrEmpty(user.ProfilePicture))
            {
                var oldPath = Path.Combine(_webHostEnvironment.WebRootPath, user.ProfilePicture.TrimStart('/'));
                if (System.IO.File.Exists(oldPath))
                    System.IO.File.Delete(oldPath);
            }

            var fileName = $"{user.Id}.jpg";
            var filePath = Path.Combine(folder, fileName);

            await System.IO.File.WriteAllBytesAsync(filePath, imageBytes);

            user.ProfilePicture = "/profile-pictures/" + fileName;
            await _userManager.UpdateAsync(user);

            TempData["Success"] = "Profile picture updated successfully!";
            return RedirectToAction("MyProfile");
        }

        [Authorize]
        public async Task<IActionResult> MyActivity()
        {
            var user = await _userManager.GetUserAsync(User);
            var myDocuments = await _context.StudentDocuments
                .Where(d => d.UserId == user.Id)
                .OrderByDescending(d => d.UploadedDate)
                .ToListAsync();
            return View(myDocuments);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
