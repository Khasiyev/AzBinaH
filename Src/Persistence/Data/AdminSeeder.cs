using Application.Options;
using Domain.Constants;
using Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Persistence.Data;

public static class AdminSeeder
{
    public static async Task SeedAsync(UserManager<User> userManager, IOptions<SeedOptions> opt)
    {
        var seed = opt.Value;

        if (string.IsNullOrWhiteSpace(seed.AdminEmail) ||
            string.IsNullOrWhiteSpace(seed.AdminPassword))
            return;

        var existing = await userManager.FindByEmailAsync(seed.AdminEmail);
        if (existing is not null) return;

        var admin = new User
        {
            UserName = seed.AdminEmail,
            Email = seed.AdminEmail,
            FullName = seed.AdminFullName,
            EmailConfirmed = true
        };

        var res = await userManager.CreateAsync(admin, seed.AdminPassword);
        if (!res.Succeeded) return;

        await userManager.AddToRoleAsync(admin, RoleNames.Admin);
    }
}
