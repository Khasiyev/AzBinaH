namespace Application.Options;

public class SeedOptions
{
    public const string SectionName = "Seed";
    public string? AdminEmail { get; set; }
    public string? AdminPassword { get; set; }
    public string AdminFullName { get; set; } = "Admin";
}
