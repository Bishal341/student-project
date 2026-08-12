using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using StudentProjectPapers.Models;

namespace StudentProjectPapers.Data {
    public static class SeedData {
        public static async Task Initialize(IServiceProvider serviceProvider)
        {
            using var scope = serviceProvider.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var configuration = scope.ServiceProvider.GetRequiredService<IConfiguration>();
            var logger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("SeedData");

            await context.Database.MigrateAsync();

            // Create roles
            if (!await roleManager.RoleExistsAsync("Admin"))
                await roleManager.CreateAsync(new IdentityRole("Admin"));

            if (!await roleManager.RoleExistsAsync("User"))
                await roleManager.CreateAsync(new IdentityRole("User"));

            // Admin passwords are read from configuration (user-secrets in Development or
            // environment variables such as AdminSeed__SuperAdminPassword in production).
            // No passwords are stored in code. If one is missing, a random password is
            // generated and logged once at first run so it can be changed after login.
            await EnsureAdminAsync(userManager, roleManager, configuration, logger,
                email: "admin@projectpapers.com",
                role: "Admin",
                fullName: "System Administrator",
                faculty: "All",
                configKey: "AdminSeed:SuperAdminPassword");

            await EnsureAdminAsync(userManager, roleManager, configuration, logger,
                email: "BIT_Admin@projectpapers.com",
                role: "Admin",
                fullName: "BIT Admin",
                faculty: "BIT",
                configKey: "AdminSeed:BitAdminPassword");

            await EnsureAdminAsync(userManager, roleManager, configuration, logger,
                email: "BBA_Admin@projectpapers.com",
                role: "Admin",
                fullName: "BBA Admin",
                faculty: "BBA",
                configKey: "AdminSeed:BbaAdminPassword");

            // Master admin (also ensures the Master_Admin role exists)
            if (!await roleManager.RoleExistsAsync("Master_Admin"))
                await roleManager.CreateAsync(new IdentityRole("Master_Admin"));

            await EnsureAdminAsync(userManager, roleManager, configuration, logger,
                email: "Master_Admin@projectpapers.com",
                role: "Master_Admin",
                fullName: "Master Admin",
                faculty: "Master",
                configKey: "AdminSeed:MasterAdminPassword");
        }

        private static async Task EnsureAdminAsync(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            ILogger logger,
            string email,
            string role,
            string fullName,
            string faculty,
            string configKey)
        {
            if (await userManager.FindByEmailAsync(email) != null)
                return;

            var user = new ApplicationUser
            {
                UserName = email,
                Email = email,
                FullName = fullName,
                Faculty = faculty,
                RegisteredDate = DateTime.Now,
                IsApproved = true,
                ApprovedDate = DateTime.Now,
                IsEmailVerified = true
            };

            var password = configuration[configKey];
            if (string.IsNullOrWhiteSpace(password))
            {
                password = GeneratePassword();
                logger.LogWarning(
                    "No password configured via {ConfigKey}. Admin account created with a generated password for {Email}. " +
                    "Use the password reset flow to set a new one.",
                    configKey, email);
            }

            var result = await userManager.CreateAsync(user, password);
            if (result.Succeeded)
            {
                if (!await roleManager.RoleExistsAsync(role))
                    await roleManager.CreateAsync(new IdentityRole(role));
                await userManager.AddToRoleAsync(user, role);
            }
        }

        private static string GeneratePassword()
        {
            const string upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
            const string lower = "abcdefghijkmnpqrstuvwxyz";
            const string digits = "23456789";
            const string all = upper + lower + digits;

            var chars = new char[16];
            var bytes = new byte[16];
            using var rng = RandomNumberGenerator.Create();

            rng.GetBytes(bytes);
            chars[0] = upper[bytes[0] % upper.Length];
            chars[1] = lower[bytes[1] % lower.Length];
            chars[2] = digits[bytes[2] % digits.Length];
            for (int i = 3; i < chars.Length; i++)
                chars[i] = all[bytes[i] % all.Length];

            rng.GetBytes(bytes);
            for (int i = chars.Length - 1; i > 0; i--)
            {
                int j = bytes[i] % (i + 1);
                (chars[i], chars[j]) = (chars[j], chars[i]);
            }

            return new string(chars);
        }
    }
}
