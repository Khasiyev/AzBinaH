namespace Application.Dtos.PropertyAdDtos;

public class GetAllPropertyAdResponse
{
    public int Id { get; set; }
    public string Title { get; set; } = null!;
    public string? Description { get; set; }
    public decimal Price { get; set; }
    public string? FirstMediaUrl { get; set; }
}
