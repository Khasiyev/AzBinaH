using Domain.Constants;
using Microsoft.AspNetCore.Identity;

namespace Persistence.Data;

public static class RoleSeeder
{
    public static async Task SeedAsync(RoleManager<IdentityRole> roleManager)
    {
        var roles = new[] { RoleNames.Admin, RoleNames.User };

        foreach (var role in roles)
        {
            var exists = await roleManager.RoleExistsAsync(role);
            if (!exists)
                await roleManager.CreateAsync(new IdentityRole(role));
        }
    }
}
