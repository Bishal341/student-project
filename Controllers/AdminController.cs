using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using StudentProjectPapers.Data;
using StudentProjectPapers.Helpers;
using StudentProjectPapers.Models;
using StudentProjectPapers.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace StudentProjectPapers.Controllers {
    [Authorize(Roles = "Admin, BIT_Admin, BBA_Admin, Master_Admin")]
    [AutoValidateAntiforgeryToken]
    public class AdminController : Controller {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _context;
        private readonly IEmailService _emailService;
        private readonly IWebHostEnvironment _webHostEnvironment;

        public AdminController(
            UserManager<ApplicationUser> userManager,
            ApplicationDbContext context,
            IEmailService emailService,
            IWebHostEnvironment webHostEnvironment)
        {
            _userManager = userManager;
            _context = context;
            _emailService = emailService;
            _webHostEnvironment = webHostEnvironment;
        }

        // Returns null for the true super admin (Faculty is empty or "All" - sees everything),
        // otherwise the faculty this admin is restricted to (e.g. "BIT", "BBA", "Master").
        private async Task<string?> GetCurrentAdminFacultyAsync()
        {
            var admin = await _userManager.GetUserAsync(User);
            if (admin == null || string.IsNullOrEmpty(admin.Faculty) || admin.Faculty == "All")
                return null;

            return admin.Faculty;
        }

        // BIT and BCS share one dashboard/admin (small student numbers), so the BIT admin
        // manages BOTH faculties. Every other faculty only manages itself.
        private static string[] GetManagedFaculties(string? faculty) => FacultyHelper.GetManagedFaculties(faculty);

        // Single source of truth: which dashboard action belongs to which faculty.
        // Add new faculties here and they automatically get routed correctly everywhere.
        // null / "All" / anything unrecognized (e.g. a future BCS admin) safely falls back to Super Admin.
        public static string GetDashboardActionForFaculty(string? faculty) => faculty switch
        {
            "BIT" => "DashboardBit",
            "BBA" => "DashboardBba",
            "Master" => "DashboardMaster",
            _ => "DashboardSuperAdmin"
        };

        // Runs before every action in this controller. Makes the current admin's
        // own dashboard action available to _AdminLayout.cshtml as ViewBag.DashboardAction,
        // so the sidebar "Dashboard" link always sends each admin to THEIR dashboard.
        public override async Task OnActionExecutionAsync(
            Microsoft.AspNetCore.Mvc.Filters.ActionExecutingContext context,
            Microsoft.AspNetCore.Mvc.Filters.ActionExecutionDelegate next)
        {
            var faculty = await GetCurrentAdminFacultyAsync();
            ViewBag.DashboardAction = GetDashboardActionForFaculty(faculty);
            await next();
        }

        // ==================== PER-ADMIN SEPARATE DASHBOARDS ====================

        public async Task<IActionResult> DashboardSuperAdmin()
        {
            await LoadDashboardStats();
            return View();
        }

        public async Task<IActionResult> DashboardMaster()
        {
            await LoadDashboardStats();
            return View();
        }

        public async Task<IActionResult> DashboardBit()
        {
            await LoadDashboardStats();
            return View();
        }

        public async Task<IActionResult> DashboardBba()
        {
            await LoadDashboardStats();
            return View();
        }

        private async Task LoadDashboardStats()
        {
            var faculty = await GetCurrentAdminFacultyAsync();
            var managedFaculties = faculty != null ? GetManagedFaculties(faculty) : null;

            var usersQuery = _userManager.Users.AsQueryable();
            if (managedFaculties != null)
                usersQuery = usersQuery.Where(u => managedFaculties.Contains(u.Faculty));

            var totalProjects = await (managedFaculties != null
                ? _context.StudentProjects.CountAsync(p => managedFaculties.Contains(p.Department))
                : _context.StudentProjects.CountAsync());
            var pendingUsers = await usersQuery.CountAsync(u => !u.IsApproved);
            var approvedUsers = await usersQuery.CountAsync(u => u.IsApproved);
            var totalUsers = await usersQuery.CountAsync();

            var recentProjectsQuery = _context.StudentProjects.AsQueryable();
            if (managedFaculties != null)
                recentProjectsQuery = recentProjectsQuery.Where(p => managedFaculties.Contains(p.Department));
            var recentProjects = await recentProjectsQuery
                .OrderByDescending(p => p.UploadedDate)
                .Take(5)
                .ToListAsync();

            ViewBag.TotalProjects = totalProjects;
            ViewBag.PendingUsers = pendingUsers;
            ViewBag.ApprovedUsers = approvedUsers;
            ViewBag.TotalUsers = totalUsers;
            ViewBag.RecentProjects = recentProjects;
        }

        public async Task<IActionResult> PendingUsers()
        {
            var faculty = await GetCurrentAdminFacultyAsync();

            var query = _userManager.Users.Where(u => !u.IsApproved);
            if (faculty != null)
            {
                var managedFaculties = GetManagedFaculties(faculty);
                query = query.Where(u => managedFaculties.Contains(u.Faculty));
            }

            var pendingUsers = await query.ToListAsync();
            return View(pendingUsers);
        }

        // POST: Admin/ApproveUser
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ApproveUser(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);

            var faculty = await GetCurrentAdminFacultyAsync();
            if (user != null && faculty != null && !GetManagedFaculties(faculty).Contains(user.Faculty))
            {
                TempData["Error"] = "You can only approve users from your own faculty.";
                return RedirectToAction("PendingUsers");
            }

            if (user != null)
            {
                user.IsApproved = true;
                user.ApprovedDate = DateTime.Now;


                user.IsEmailVerified = false;//Testing ... change it to false after completing
                user.OtpCode = null;
                user.OtpExpiry = null;

                var result = await _userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    // Generate Identity email confirmation token
                    var verifyToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                    var verifyLink = Url.Action("VerifyEmail", "Account",
                        new { token = verifyToken, email = user.Email }, Request.Scheme);

                    var emailBody = $@"
        <div style='font-family:Arial,sans-serif;max-width:500px;margin:0 auto;background:#F6F7FB;padding:0;border-radius:14px;overflow:hidden;'>
            <div style='background:#081547;padding:36px 20px;text-align:center;'>
            <div style='text-align:center;margin-bottom:25px;'>
               <h1 style='color:#fff;margin:0;font-size:22px;font-weight:800;'>Texas College</h1>
                <p style='color:#C6C6F0;margin:6px 0 0;font-size:24px;'>Student Project Papers</p>
                
            </div>
            <div style='background:#fff;border-radius:14px;padding:30px;box-shadow:0 2px 8px rgba(36,29,140,0.08);'>
                <h2 style='color:#1F2333;margin-top:0;font-size:18px;'>Hello {user.FullName},</h2>
                <p style='color:#6B7180;font-size:14px;line-height:1.6;'>
                    Your account has been approved by the administrator!
                </p>
                <p style='color:#6B7180;font-size:14px;line-height:1.6;'>
                    Click the button below to verify your identity and access your account:
                </p>
                <div style='text-align:center;margin:30px 0;'>
                    <a href='{verifyLink}'
                       style='background:#0d6efd;
                              color:#fff;padding:14px 32px;border-radius:10px;
                              text-decoration:none;font-weight:700;font-size:15px;
                              display:inline-block;'>
                         Verify It's You
                    </a>
                </div>
                <hr style='border:none;border-top:1px solid #E7E8F1;margin:25px 0;'/>
                <p style='color:#9CA3AF;font-size:12px;'>
                    🔒 If you didn't register on Texas Library, you can safely ignore this email.
                </p>
            </div>
            <p style='text-align:center;color:#9CA3AF;font-size:16px;margin-top:20px;'>
                © 2026 Student Project Papers — All Rights Reserved
            </p>
        </div>";

                    await _emailService.SendEmailAsync(user.Email, "Account Approved - Texas Library", emailBody);
                    TempData["Success"] = $"User {user.Email} approved and verification email sent!";
                }
                else
                {
                    TempData["Error"] = "Error approving user.";
                }
            }
            return RedirectToAction("PendingUsers");
        }

        // POST: Admin/RejectUser
        // Rejecting permanently deletes the account (no soft-delete pattern exists in the codebase),
        // which frees up the email for re-registration. Deleted rows never appear in the pending
        // query (WHERE !IsApproved) or the pending count, so no extra filtering is needed.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RejectUser(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return Json(new { success = false, message = "User not found." });

            var faculty = await GetCurrentAdminFacultyAsync();
            if (faculty != null && !GetManagedFaculties(faculty).Contains(user.Faculty))
                return Json(new { success = false, message = "You can only reject users from your own faculty." });

            var result = await _userManager.DeleteAsync(user);

            if (result.Succeeded)
                return Json(new { success = true, message = $"User {user.Email} rejected and their account deleted." });

            return Json(new { success = false, message = "Error rejecting user." });
        }

        [HttpGet]
        public async Task<IActionResult> UploadProject()
        {
            var faculty = await GetCurrentAdminFacultyAsync();
            ViewBag.LockedFaculty = faculty;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequestSizeLimit(10 * 1024 * 1024)]
        public async Task<IActionResult> UploadProject(UploadProjectViewModel model)
        {
            var faculty = await GetCurrentAdminFacultyAsync();

            if (faculty != null)
            {
                model.Department = faculty;
                ModelState.Remove(nameof(model.Department));
            }

            if (ModelState.IsValid)
            {
                if (model.PdfFile == null || model.PdfFile.Length == 0)
                {
                    ModelState.AddModelError("PdfFile", "Please select a PDF file.");
                }
                else if (!IsAllowedProjectFile(model.PdfFile, out var fileError))
                {
                    ModelState.AddModelError("PdfFile", fileError);
                }
                else
                {
                    // PRIVATE storage: ContentRootPath keeps these files OUTSIDE wwwroot so
                    // they can never be served by the static-file middleware. Do NOT move
                    // this back under WebRootPath.
                    var uploadsFolder = Path.Combine(_webHostEnvironment.ContentRootPath, "private-uploads", "projects");
                    if (!Directory.Exists(uploadsFolder))
                        Directory.CreateDirectory(uploadsFolder);

                    // The stored name is GUID-led; the original filename is first sanitized
                    // to a safe allow-list (letters, digits, dash, underscore, dot) so client
                    // input can never contribute a directory component to the on-disk path.
                    var originalFileName = model.PdfFile.FileName ?? string.Empty;
                    var safeFileName = SanitizeProjectFileName(originalFileName);
                    var uniqueFileName = $"{Guid.NewGuid()}_{safeFileName}";
                    var filePath = Path.Combine(uploadsFolder, uniqueFileName);

                    // Defense in depth: even after sanitization, verify the combined path
                    // still resolves inside the target directory before writing anything.
                    if (!IsPathWithinDirectory(filePath, uploadsFolder))
                    {
                        ModelState.AddModelError("PdfFile", "The uploaded file name is invalid.");
                    }
                    else
                    {
                        using (var stream = new FileStream(filePath, FileMode.Create))
                        {
                            await model.PdfFile.CopyToAsync(stream);
                        }

                        var project = new StudentProject
                        {
                            LCID = model.LCID,
                            StudentName = model.StudentName,
                            SubmittedDate = model.SubmittedDate,
                            ProjectTitle = model.ProjectTitle,
                            Description = model.Description,
                            // Store just the filename (not a public URL). DownloadProject and
                            // DeleteProject reconstruct the full path from ContentRootPath at
                            // read time (private-uploads/projects, OUTSIDE wwwroot).
                            FilePath = uniqueFileName,
                            // Sanitized name only: safe for the Content-Disposition download
                            // name and any UI display; never used as an on-disk path segment.
                            OriginalFileName = safeFileName,
                            UploadedDate = DateTime.Now,
                            SupervisorName = model.SupervisorName,
                            Department = model.Department,
                            Year = model.Year
                        };

                        _context.StudentProjects.Add(project);
                        await _context.SaveChangesAsync();

                        TempData["Success"] = "Project uploaded successfully!";
                        return RedirectToAction(GetDashboardActionForFaculty(faculty));
                    }
                }
            }
            ViewBag.LockedFaculty = faculty;
            return View(model);
        }

        public async Task<IActionResult> ManageProjects()
        {
            var faculty = await GetCurrentAdminFacultyAsync();

            var query = _context.StudentProjects.AsQueryable();
            if (faculty != null)
            {
                var managedFaculties = GetManagedFaculties(faculty);
                query = query.Where(p => managedFaculties.Contains(p.Department));
            }

            var projects = await query
                .OrderByDescending(p => p.UploadedDate)
                .ToListAsync();
            return View(projects);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteProject(int id)
        {
            var project = await _context.StudentProjects.FindAsync(id);

            var faculty = await GetCurrentAdminFacultyAsync();
            if (project != null && faculty != null && !GetManagedFaculties(faculty).Contains(project.Department))
            {
                TempData["Error"] = "You can only delete projects from your own faculty.";
                return RedirectToAction("ManageProjects");
            }

            if (project != null)
            {
                var filePath = ResolvePrivateProjectPath(project);
                if (System.IO.File.Exists(filePath))
                    System.IO.File.Delete(filePath);

                _context.StudentProjects.Remove(project);
                await _context.SaveChangesAsync();

                TempData["Success"] = "Project deleted successfully!";
            }
            return RedirectToAction("ManageProjects");
        }

        [HttpGet]
        public async Task<IActionResult> VerifyDocuments()
        {
            var faculty = await GetCurrentAdminFacultyAsync();

            var query = _context.StudentDocuments
                .Where(d => d.Status == DocumentStatus.Pending);

            if (faculty != null)
            {
                var managedFaculties = GetManagedFaculties(faculty);
                var facultyUserIds = _userManager.Users
                    .Where(u => managedFaculties.Contains(u.Faculty))
                    .Select(u => u.Id);
                query = query.Where(d => d.UserId != null && facultyUserIds.Contains(d.UserId));
            }

            var documents = await query
                .OrderByDescending(d => d.UploadedDate)
                .ToListAsync();
            return View(documents);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyDocument(int id)
        {
            var document = await _context.StudentDocuments.FindAsync(id);
            if (document != null && !await CanAdminAccessDocumentAsync(document))
            {
                TempData["Error"] = "You can only verify documents from your own faculty.";
                return RedirectToAction("VerifyDocuments");
            }
            if (document != null)
            {
                document.Status = DocumentStatus.Verified;
                document.VerifiedDate = DateTime.Now;
                await _context.SaveChangesAsync();
                TempData["Success"] = "Document verified successfully.";
            }
            return RedirectToAction("VerifyDocuments");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RejectDocument(int id, string reason)
        {
            var document = await _context.StudentDocuments.FindAsync(id);
            if (document != null && !await CanAdminAccessDocumentAsync(document))
            {
                TempData["Error"] = "You can only reject documents from your own faculty.";
                return RedirectToAction("VerifyDocuments");
            }
            if (document != null)
            {
                document.Status = DocumentStatus.Rejected;
                document.RejectionReason = reason;
                await _context.SaveChangesAsync();
                TempData["Success"] = "Document rejected.";
            }
            return RedirectToAction("VerifyDocuments");
        }

        /// <summary>
        /// One-time migration for the private-documents fix.
        /// Copies every file from the old public location (wwwroot/uploads/documents)
        /// into private-uploads/documents (ContentRootPath-relative, OUTSIDE wwwroot) and
        /// rewrites StudentDocument.FilePath from "/uploads/documents/&lt;file&gt;" to just
        /// "&lt;file&gt;". Source files are COPIED, NOT deleted — verify documents still open via
        /// Home/ViewDocument and Home/DownloadDocument, then delete wwwroot/uploads/documents
        /// manually. Idempotent: already-migrated rows/files are skipped.
        /// </summary>
        [Authorize(Roles = "Admin, Master_Admin")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> MigratePrivateDocuments()
        {
            var sourceDir = Path.Combine(_webHostEnvironment.WebRootPath, "uploads", "documents");
            var targetDir = Path.Combine(_webHostEnvironment.ContentRootPath, "private-uploads", "documents");

            var filesMoved = 0;
            var filesSkipped = 0;
            var rowsUpdated = 0;
            var rowsSkipped = 0;
            var errors = new List<string>();

            Directory.CreateDirectory(targetDir);

            if (Directory.Exists(sourceDir))
            {
                foreach (var file in Directory.GetFiles(sourceDir))
                {
                    var fileName = Path.GetFileName(file);
                    var dest = Path.Combine(targetDir, fileName);
                    try
                    {
                        if (System.IO.File.Exists(dest))
                        {
                            filesSkipped++;
                        }
                        else
                        {
                            System.IO.File.Copy(file, dest);
                            filesMoved++;
                        }
                    }
                    catch (Exception ex)
                    {
                        errors.Add($"Copy failed for {fileName}: {ex.Message}");
                    }
                }
            }

            var documents = await _context.StudentDocuments.ToListAsync();
            foreach (var doc in documents)
            {
                if (string.IsNullOrEmpty(doc.FilePath) ||
                    !doc.FilePath.StartsWith("/uploads/documents/", StringComparison.OrdinalIgnoreCase))
                {
                    rowsSkipped++;
                    continue;
                }

                doc.FilePath = doc.FilePath.Substring("/uploads/documents/".Length).TrimStart('/');
                rowsUpdated++;
            }

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                errors.Add($"DB update failed: {ex.Message}");
            }

            TempData["Success"] =
                $"Migration complete: {filesMoved} files copied, {filesSkipped} already present, " +
                $"{rowsUpdated} DB rows updated, {rowsSkipped} rows already migrated. " +
                "Verify documents still open before deleting wwwroot/uploads/documents.";

            if (errors.Count > 0)
                TempData["Error"] = string.Join(" | ", errors.Take(5));

            return RedirectToAction("DashboardSuperAdmin");
        }

        private async Task<bool> CanAdminAccessDocumentAsync(StudentDocument document)
        {
            var faculty = await GetCurrentAdminFacultyAsync();
            if (faculty == null) return true; // Master admin sees everything
            if (document.UserId == null) return false;

            var owner = await _userManager.FindByIdAsync(document.UserId);
            return owner != null && GetManagedFaculties(faculty).Contains(owner.Faculty);
        }

        // ==================== PROJECT UPLOAD VALIDATION (server-side) ====================

        // Only .pdf is allowed for project uploads (the view documents PDF-only, 10MB max).
        // The whitelist is compared case-insensitively; Path.GetExtension returns only the
        // LAST extension, so double-extension tricks like "report.PDF.html" fail because
        // ".html" is not on the whitelist.
        private static readonly string[] AllowedProjectFileExtensions = { ".pdf" };
        private const long MaxProjectFileSize = 10 * 1024 * 1024; // 10MB

        private static bool IsAllowedProjectFile(IFormFile file, out string error)
        {
            var extension = Path.GetExtension(file.FileName);
            if (string.IsNullOrEmpty(extension) ||
                !AllowedProjectFileExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase))
            {
                error = "Only PDF files are allowed. Please select a .pdf file.";
                return false;
            }

            if (file.Length > MaxProjectFileSize)
            {
                error = "File size must not exceed 10MB.";
                return false;
            }

            // Magic-byte verification: never trust the browser-supplied Content-Type or the
            // filename alone. A real PDF begins with the "%PDF-" signature
            // (0x25 0x50 0x44 0x46 0x2D); reject anything that doesn't.
            using var stream = file.OpenReadStream();
            var header = new byte[5];
            var read = stream.Read(header, 0, header.Length);
            if (read < header.Length ||
                header[0] != 0x25 || header[1] != 0x50 || header[2] != 0x44 ||
                header[3] != 0x46 || header[4] != 0x2D)
            {
                error = "The uploaded file is not a valid PDF.";
                return false;
            }

            error = null;
            return true;
        }

        // Strips any directory components (Path.GetFileName) and replaces every character
        // outside a safe allow-list (letters, digits, dash, underscore, dot) so the result
        // can never contain a path separator or otherwise escape the upload folder.
        private static string SanitizeProjectFileName(string fileName)
        {
            var name = Path.GetFileName(fileName ?? string.Empty);
            var sanitized = new string(name.Select(c =>
                char.IsLetterOrDigit(c) || c == '-' || c == '_' || c == '.' ? c : '_').ToArray()).Trim('.');

            return string.IsNullOrEmpty(sanitized) ? "project" : sanitized;
        }

        // Defense in depth: confirms the combined path still resolves inside the intended
        // target directory, even if a traversal somehow slipped past sanitization.
        private static bool IsPathWithinDirectory(string fullPath, string targetDirectory)
        {
            var fullPathValue = Path.GetFullPath(fullPath);
            var directoryPrefix =
                Path.GetFullPath(targetDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            return fullPathValue.StartsWith(directoryPrefix, StringComparison.Ordinal);
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

        [HttpGet]
        public async Task<JsonResult> GetPendingDocumentsCount()
        {
            try
            {
                var faculty = await GetCurrentAdminFacultyAsync();

                var query = _context.StudentDocuments
                    .Where(d => d.Status == DocumentStatus.Pending);

                if (faculty != null)
                {
                    var managedFaculties = GetManagedFaculties(faculty);
                    var facultyUserIds = _userManager.Users
                        .Where(u => managedFaculties.Contains(u.Faculty))
                        .Select(u => u.Id);
                    query = query.Where(d => d.UserId != null && facultyUserIds.Contains(d.UserId));
                }

                var pendingCount = await query.CountAsync();
                return Json(new { count = pendingCount });
            }
            catch (Exception ex)
            {
                return Json(new { count = 0, error = ex.Message });
            }
        }

        [HttpGet]
        public async Task<JsonResult> GetPendingUsersCount()
        {
            try
            {
                var faculty = await GetCurrentAdminFacultyAsync();

                var usersQuery = _userManager.Users.Where(u => !u.IsApproved);
                if (faculty != null)
                {
                    var managedFaculties = GetManagedFaculties(faculty);
                    usersQuery = usersQuery.Where(u => managedFaculties.Contains(u.Faculty));
                }

                var pendingCount = await usersQuery.CountAsync();
                return Json(new { count = pendingCount });
            }
            catch (Exception ex)
            {
                return Json(new { count = 0, error = ex.Message });
            }
        }

        [HttpGet]
        public async Task<IActionResult> Users()
        {
            var faculty = await GetCurrentAdminFacultyAsync();

            var usersQuery = _userManager.Users.AsQueryable();
            if (faculty != null)
            {
                var managedFaculties = GetManagedFaculties(faculty);
                usersQuery = usersQuery.Where(u => managedFaculties.Contains(u.Faculty));
            }

            var users = await usersQuery.ToListAsync();
            var userViewModels = new List<UserManagementViewModel>();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                var role = roles.FirstOrDefault() ?? "User";

                // User Management should only list students/alumni, not other admin accounts.
                if (role.Contains("Admin"))
                    continue;

                var mustChangePassword = !await _userManager.HasPasswordAsync(user) ||
                                         await _userManager.GetAuthenticationTokenAsync(user, "Default", "MustChangePassword") == "true";

                userViewModels.Add(new UserManagementViewModel
                {
                    Id = user.Id,
                    FullName = user.FullName,
                    UserName = user.UserName,
                    Email = user.Email,
                    PhoneNumber = user.PhoneNumber,
                    RegisteredDate = user.RegisteredDate,
                    ApprovedDate = user.ApprovedDate,
                    IsApproved = user.IsApproved,
                    Role = role,
                    PasswordStatus = await GetPasswordStatus(user),
                    LastLoginDate = null,
                    MustChangePassword = mustChangePassword
                });
            }

            ViewBag.TotalUsers = userViewModels.Count;
            ViewBag.ApprovedUsers = userViewModels.Count(u => u.IsApproved);
            ViewBag.PendingUsers = userViewModels.Count(u => !u.IsApproved);

            return View(userViewModels);
        }

        [HttpGet]
        public async Task<IActionResult> UserDetails(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();

            var roles = await _userManager.GetRolesAsync(user);
            var role = roles.FirstOrDefault() ?? "User";

            var mustChangePassword = !await _userManager.HasPasswordAsync(user) ||
                                     await _userManager.GetAuthenticationTokenAsync(user, "Default", "MustChangePassword") == "true";

            var model = new UserDetailsViewModel
            {
                Id = user.Id,
                FullName = user.FullName,
                UserName = user.UserName,
                Email = user.Email,
                PhoneNumber = user.PhoneNumber,
                RegisteredDate = user.RegisteredDate,
                ApprovedDate = user.ApprovedDate,
                IsApproved = user.IsApproved,
                Role = role,
                EmailConfirmed = user.EmailConfirmed,
                PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                TwoFactorEnabled = user.TwoFactorEnabled,
                AccessFailedCount = user.AccessFailedCount,
                LockoutEnd = user.LockoutEnd,
                PasswordStatus = await GetPasswordStatus(user),
                MustChangePassword = mustChangePassword
            };

            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> ResetUserPassword(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();

            var model = new AdminResetPasswordViewModel
            {
                UserId = user.Id,
                UserEmail = user.Email,
                UserName = user.FullName,
                SendEmailNotification = true,
                MustChangePassword = true
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetUserPassword(AdminResetPasswordViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null) return NotFound();

            try
            {
                // Never generate, email, or log a plaintext password. Instead issue a
                // single-use, time-limited Identity reset token and email a link that
                // lets the user set their own new password (Account/ResetPassword).
                var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
                var resetLink = Url.Action("ResetPassword", "Account",
                    new { token = resetToken, email = user.Email }, Request.Scheme);

                if (model.MustChangePassword)
                    await _userManager.SetAuthenticationTokenAsync(user, "Default", "MustChangePassword", "true");

                if (model.SendEmailNotification)
                {
                    var emailBody = $@"
        <div style='font-family:Arial,sans-serif;max-width:500px;margin:0 auto;background:#F6F7FB;padding:0;border-radius:14px;overflow:hidden;'>
            <div style='background:#081547;padding:36px 20px;text-align:center;'>
                <h1 style='color:#fff;margin:0;font-size:22px;font-weight:800;'>Texas College</h1>
                <p style='color:#C6C6F0;margin:6px 0 0;font-size:24px;'>Student Project Papers</p>
            </div>
            <div style='background:#fff;border-radius:14px;padding:30px;box-shadow:0 2px 8px rgba(36,29,140,0.08);'>
                <h2 style='color:#1F2333;margin-top:0;font-size:18px;'>Hello {user.FullName},</h2>
                <p style='color:#6B7180;font-size:14px;line-height:1.6;'>
                    Your password has been reset by the administrator.
                </p>
                <p style='color:#6B7180;font-size:14px;line-height:1.6;'>
                    Click the button below to set a new password. This link is single-use and expires shortly.
                </p>
                <div style='text-align:center;margin:30px 0;'>
                    <a href='{resetLink}'
                       style='background:#0d6efd;color:#fff;padding:14px 32px;border-radius:10px;
                              text-decoration:none;font-weight:700;font-size:15px;display:inline-block;'>
                         Set New Password
                    </a>
                </div>
                <hr style='border:none;border-top:1px solid #E7E8F1;margin:25px 0;'/>
                {(model.MustChangePassword ? "<p style='color:#6B7180;font-size:14px;line-height:1.6;'><strong>Important:</strong> You will be required to set a new password before you can continue.</p>" : "")}
                <p style='color:#9CA3AF;font-size:12px;'>
                    🔒 If you didn't request this, you can safely ignore this email.
                </p>
            </div>
            <p style='text-align:center;color:#9CA3AF;font-size:16px;margin-top:20px;'>
                © 2026 Student Project Papers — All Rights Reserved
            </p>
        </div>";

                    await _emailService.SendEmailAsync(user.Email, "Password Reset - Texas Library", emailBody);
                }

                TempData["Success"] = $"A password reset link has been sent to {user.Email}!";
                return RedirectToAction(nameof(Users));
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("", $"Error sending password reset link: {ex.Message}");
                return View(model);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ToggleUserApproval(string userId, bool isApproved)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return Json(new { success = false, message = "User not found" });

            var faculty = await GetCurrentAdminFacultyAsync();
            if (faculty != null && !GetManagedFaculties(faculty).Contains(user.Faculty))
                return Json(new { success = false, message = "You can only manage users from your own faculty" });

            user.IsApproved = isApproved;
            if (isApproved) user.ApprovedDate = DateTime.Now;

            var result = await _userManager.UpdateAsync(user);

            if (result.Succeeded)
            {
                if (isApproved)
                {
                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                    var resetLink = Url.Action("ResetPassword", "Account",
                        new { token, email = user.Email }, Request.Scheme);

                    var emailBody = $@"
                        <h2>Account Approved!</h2>
                        <p>Dear {user.FullName},</p>
                        <p>Your account has been approved by the administrator.</p>
                        <p>Click <a href='{resetLink}'>here</a> to set your password and access the system.</p>";

                    await _emailService.SendEmailAsync(user.Email, "Account Approved - Texas Library", emailBody);
                }

                return Json(new { success = true, message = $"User {(isApproved ? "approved" : "suspended")} successfully" });
            }

            return Json(new { success = false, message = "Error updating user status" });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForceChangePassword(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return Json(new { success = false, message = "User not found" });

            // Same faculty-scope gate as ToggleUserApproval: faculty admins may only
            // force a password change on users from their own managed faculties.
            var faculty = await GetCurrentAdminFacultyAsync();
            if (faculty != null && !GetManagedFaculties(faculty).Contains(user.Faculty))
                return Json(new { success = false, message = "You can only manage users from your own faculty" });

            await _userManager.SetAuthenticationTokenAsync(user, "Default", "MustChangePassword", "true");
            return Json(new { success = true, message = "User will be forced to change password at next login" });
        }

        private async Task<string> GetPasswordStatus(ApplicationUser user)
        {
            if (!await _userManager.HasPasswordAsync(user))
                return "No Password Set";

            var mustChange = await _userManager.GetAuthenticationTokenAsync(user, "Default", "MustChangePassword");
            if (mustChange == "true")
                return "Must Change at Next Login";

            return "Active";
        }
    }
}