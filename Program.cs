using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using StudentProjectPapers.Data;
using StudentProjectPapers.Models;
using StudentProjectPapers.Services;

var builder = WebApplication.CreateBuilder(args);

// Brute-force protection tuning for this deployment.
// Web + mobile login lockout: 5 failed attempts locks the account for 15 minutes.
// Mobile login rate limit: 5 requests per IP per 5 minutes (429 when exceeded).
// Mobile contact rate limit: 5 requests per IP per minute.
const int LockoutMaxFailedAccessAttempts = 5;
const int LockoutWindowMinutes = 15;
const int LoginRateLimitPermit = 5;
const int LoginRateLimitWindowMinutes = 5;
const int ContactRateLimitPermit = 5;
const int ContactRateLimitWindowMinutes = 1;

// Load secrets.json in Development so secret config values (e.g. the database
// connection string, SMTP password and JWT signing key) resolve from user-secrets
// instead of being baked into a committed config file.
if (builder.Environment.IsDevelopment())
{
    builder.Configuration.AddUserSecrets<Program>();
}

// Fail fast when critical secrets are missing, empty or still set to a committed
// placeholder. Never fall back to a weak or publicly-known signing key / credentials.
const string MissingPlaceholderMarker = "CHANGE_ME_";
const string PlaceholderMarker = "REPLACE_ME_";

var jwtSecret = builder.Configuration["Jwt:SecretKey"];
if (string.IsNullOrWhiteSpace(jwtSecret)
    || jwtSecret.Contains(MissingPlaceholderMarker, StringComparison.OrdinalIgnoreCase)
    || jwtSecret.Contains(PlaceholderMarker, StringComparison.OrdinalIgnoreCase)
    || jwtSecret.Length < 32)
{
    throw new InvalidOperationException(
        "Jwt:SecretKey is missing, too short, or still set to the placeholder value. " +
        "Configure a real random secret of at least 64 characters before starting the app, e.g. " +
        "via user-secrets (Jwt:SecretKey) or the Jwt__SecretKey environment variable. " +
        "The app refuses to start with a weak or publicly-known signing key.");
}

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
if (string.IsNullOrWhiteSpace(connectionString)
    || connectionString.Contains(MissingPlaceholderMarker, StringComparison.OrdinalIgnoreCase)
    || connectionString.Contains(PlaceholderMarker, StringComparison.OrdinalIgnoreCase))
{
    throw new InvalidOperationException(
        "The database connection string (ConnectionStrings:DefaultConnection) is missing or still " +
        "contains the placeholder password. Configure the real connection string via user-secrets " +
        "(ConnectionStrings:DefaultConnection) or the ConnectionStrings__DefaultConnection " +
        "environment variable before starting the app.");
}

var smtpUsername = builder.Configuration["EmailSettings:SmtpUsername"];
var smtpPassword = builder.Configuration["EmailSettings:SmtpPassword"];
if (string.IsNullOrWhiteSpace(smtpUsername)
    || smtpUsername.Contains(MissingPlaceholderMarker, StringComparison.OrdinalIgnoreCase)
    || smtpUsername.Contains(PlaceholderMarker, StringComparison.OrdinalIgnoreCase)
    || string.IsNullOrWhiteSpace(smtpPassword)
    || smtpPassword.Contains(MissingPlaceholderMarker, StringComparison.OrdinalIgnoreCase)
    || smtpPassword.Contains(PlaceholderMarker, StringComparison.OrdinalIgnoreCase))
{
    throw new InvalidOperationException(
        "EmailSettings:SmtpUsername and/or EmailSettings:SmtpPassword is missing or still set to the " +
        "committed placeholder value. Configure the real SMTP credentials via user-secrets " +
        "(EmailSettings:SmtpUsername, EmailSettings:SmtpPassword) or the EmailSettings__SmtpUsername / " +
        "EmailSettings__SmtpPassword environment variables before starting the app.");
}

// Add services to the container.
builder.Services.AddScoped<StudentProjectPapers.Filters.MustChangePasswordRedirectFilter>();
builder.Services.AddControllersWithViews(options =>
{
    // Force web users with the MustChangePassword flag set onto the change-password
    // page until they set a new password. The filter itself exempts the Account
    // login/password actions and ignores /api/* (JWT) requests.
    options.Filters.Add<StudentProjectPapers.Filters.MustChangePasswordRedirectFilter>();
});
builder.Services.AddControllers(); // attribute-routed Mobile API

// Configure Database
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Configure Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.User.RequireUniqueEmail = true;
    options.Lockout.MaxFailedAccessAttempts = LockoutMaxFailedAccessAttempts;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(LockoutWindowMinutes);
    options.Lockout.AllowedForNewUsers = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Rate limiting for the public (unauthenticated) mobile endpoints that accept
// attacker-controlled input. Policies partition by client IP; a single user
// cannot exhaust the shared budget for everyone else.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.AddPolicy("mobileLogin", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString(),
            factory: _ => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = LoginRateLimitPermit,
                QueueLimit = 0,
                Window = TimeSpan.FromMinutes(LoginRateLimitWindowMinutes)
            }));

    options.AddPolicy("mobileContact", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString(),
            factory: _ => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = ContactRateLimitPermit,
                QueueLimit = 0,
                Window = TimeSpan.FromMinutes(ContactRateLimitWindowMinutes)
            }));

    options.AddPolicy("webLogin", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString(),
            factory: _ => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 10,
                QueueLimit = 0,
                Window = TimeSpan.FromMinutes(5)
            }));
});

// Configure Email Settings
builder.Services.Configure<EmailSettings>(builder.Configuration.GetSection("EmailSettings"));
builder.Services.AddTransient<IEmailService, EmailService>();

// Configure Cookie Settings
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Home/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
    options.SlidingExpiration = true;
});

// Configure JWT Bearer auth for the mobile API.
// Registered as an ADDITIONAL scheme so the website's cookie auth stays the default;
// controllers opt into "Bearer" via [Authorize(AuthenticationSchemes = "Bearer")].
var requireHttpsMetadata = !builder.Environment.IsDevelopment();
builder.Services.AddAuthentication()
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        options.RequireHttpsMetadata = requireHttpsMetadata;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:SecretKey"]))
        };
    });

if (!builder.Environment.IsDevelopment() && !requireHttpsMetadata)
{
    throw new InvalidOperationException("RequireHttpsMetadata must be true outside Development.");
}

var app = builder.Build();

// Create roles and admin user
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    await SeedData.Initialize(services);
}

// ---------------------------------------------------------------------------
// Startup operational warning (FIX 5): detect if the old public document
// directory still exists after the MigratePrivateDocuments one-time migration.
// wwwroot/uploads/documents is served by the static-file middleware and exposes
// private student documents to anyone who knows (or guesses) the filename.
// This is a WARNING, not a crash — the app can still run, but an admin must
// manually verify the migration ran cleanly, then delete the directory.
//
// app.Logger is the ILogger<WebApplication> instance available on WebApplication
// since .NET 6. No scoped service or extra using is required here.
// ---------------------------------------------------------------------------
var publicDocDir = Path.Combine(app.Environment.WebRootPath, "uploads", "documents");
if (Directory.Exists(publicDocDir))
{
    app.Logger.LogWarning(
        "SECURITY: wwwroot/uploads/documents still exists at {Path}. " +
        "This directory is publicly servable and may expose private student documents. " +
        "Run Admin → MigratePrivateDocuments, verify documents open correctly via " +
        "Home/ViewDocument, then delete the directory manually.",
        publicDocDir);
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

// ---------------------------------------------------------------------------
// Security response headers (audit finding F9).
//
// Registered AFTER UseExceptionHandler on purpose: the exception handler clears
// the response (headers included) and re-runs the downstream pipeline for the
// error page, so the headers middleware must sit inside it to also cover error
// pages. It still runs BEFORE UseStaticFiles/UseRouting, so every HTML page,
// static asset and API response gets the headers.
//
// HSTS is deliberately NOT set here: app.UseHsts() above already emits it
// outside Development. Duplicating it would produce a redundant header.
// ---------------------------------------------------------------------------
const bool EnforceCsp = true; // flip to true after manual click-through shows no violations

app.Use(async (context, next) =>
{
    // Per-request CSP nonce: generated once, before the response is configured,
    // so every inline <script> rendered by any view in this request can carry it.
    var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    context.Items["CspNonce"] = nonce;

    context.Response.OnStarting(() =>
    {
        context.Response.Headers["X-Frame-Options"] = "DENY";
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
        context.Response.Headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()";

        // Sources inventoried from all .cshtml files (see F9 fix note):
        // scripts: code.jquery.com, cdn.jsdelivr.net, cdn.datatables.net, cdnjs.cloudflare.com
        // styles:  cdn.jsdelivr.net, cdnjs.cloudflare.com, cdn.datatables.net, fonts.googleapis.com
        // fonts:   fonts.gstatic.com (Google webfonts), cdnjs.cloudflare.com (Font Awesome webfonts)
        // Inline <script> blocks are allowed via the per-request nonce (script-src
        // has NO 'unsafe-inline'), so injected inline scripts are blocked. style-src
        // keeps 'unsafe-inline' because of the many style="..." attributes and
        // <style> blocks, which cannot execute code.
        var csp =
            "default-src 'self'; " +
            "base-uri 'self'; " +
            "object-src 'none'; " +
            "frame-ancestors 'none'; " +
            "form-action 'self'; " +
            "script-src 'self' 'nonce-" + nonce + "' " +
            "https://code.jquery.com https://cdn.jsdelivr.net https://cdn.datatables.net https://cdnjs.cloudflare.com; " +
            "style-src 'self' 'unsafe-inline' " +
            "https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.datatables.net https://fonts.googleapis.com; " +
            "font-src 'self' data: https://cdnjs.cloudflare.com https://fonts.gstatic.com; " +
            "img-src 'self' data: https:; " +
            "connect-src 'self'";

        context.Response.Headers[EnforceCsp ? "Content-Security-Policy" : "Content-Security-Policy-Report-Only"] = csp;

        return Task.CompletedTask;
    });

    await next();
});

// Allow HTTP from Android emulator / LAN for mobile API + static uploads
if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
}

// Static files: serve ONLY the explicitly allowed public folders from wwwroot
// (css, js, image, lib, favicon, and profile-pictures). Do NOT switch back to a bare
// root-wide app.UseStaticFiles(): project PDFs and private student documents are stored
// in private-uploads/ (relative to ContentRootPath, deliberately OUTSIDE wwwroot) and the
// web server must never serve them, or any future private folder accidentally placed
// under wwwroot.
app.UseWhen(context =>
{
    var path = context.Request.Path.Value ?? string.Empty;

    var isPublicFolder =
        path.StartsWith("/css", StringComparison.Ordinal) ||
        path.StartsWith("/js", StringComparison.Ordinal) ||
        path.StartsWith("/image", StringComparison.Ordinal) ||
        path.StartsWith("/lib", StringComparison.Ordinal) ||
        path.StartsWith("/favicon", StringComparison.Ordinal) ||
        path.StartsWith("/profile-pictures", StringComparison.Ordinal);

    // Hard deny-list: project PDFs (/uploads), private student documents and
    // private-uploads are never served, even as defense-in-depth if such a folder is
    // ever (wrongly) recreated under wwwroot. /uploads is also deliberately absent from
    // isPublicFolder above, so the middleware can never serve anything under it.
    var isPrivatePath =
        path.StartsWith("/uploads", StringComparison.Ordinal) ||
        path.StartsWith("/private-uploads", StringComparison.Ordinal);

    return isPublicFolder && !isPrivatePath;
}, subApp =>
{
    subApp.UseStaticFiles();
});
app.UseRouting();
app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers(); // /api/mobile/*
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();