namespace API.Extensions;

public static class WebApplicationExtensions
{
    public static WebApplication UseApplicationPipeline(this WebApplication app)
    {
        // Authentication MÜTLƏQ Authorization-dan əvvəl olmalıdır
        app.UseAuthentication();
        app.UseAuthorization();

        return app;
    }
}
