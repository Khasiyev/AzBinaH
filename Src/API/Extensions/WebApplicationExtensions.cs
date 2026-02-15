using Application.Options;
using Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Persistence.Data;

namespace API.Extensions;

public static class WebApplicationExtensions
{
    public static WebApplication UseApplicationPipeline(this WebApplication app)
    {
        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }

        app.UseHttpsRedirection();

        app.UseRouting();

        // Authentication MÜTLƏQ Authorization-dan əvvəl olmalıdır
        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();

        return app;
    }

    //seed (app başlayanda 1 dəfə)
    public static WebApplication SeedAuth(this WebApplication app)
    {
        using var scope = app.Services.CreateScope();

        // Rollar
        RoleSeeder.SeedAsync(
            scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>()
        ).GetAwaiter().GetResult();

        // Dev-də admin seed
        if (app.Environment.IsDevelopment())
        {
            AdminSeeder.SeedAsync(
                scope.ServiceProvider.GetRequiredService<UserManager<User>>(),
                scope.ServiceProvider.GetRequiredService<IOptions<SeedOptions>>()
            ).GetAwaiter().GetResult();
        }

        return app;
    }
}
