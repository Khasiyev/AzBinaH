namespace Application.Dtos.PropertyAdDtos;

public class UpdatePropertyAdRequest
{
    public int Id { get; set; }
    public string? Description { get; set; }
    public decimal? Price { get; set; }
    public int? FloorNumber { get; set; }
    public int? TotalFloors { get; set; }
    public int[]? RemoveMediaIds { get; set; }
    public List<MediaUploadInput>? AddMedia { get; set; }
}
