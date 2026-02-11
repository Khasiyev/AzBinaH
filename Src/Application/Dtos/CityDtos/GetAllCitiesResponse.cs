namespace Application.Dtos.CityDtos;

public class GetAllCitiesResponse
{
    public int Id { get; set; }
    public string Name { get; set; } = null!;
    public DateTime CreatedAt { get;  }
    public DateTime UpdatedAt { get; }
}
