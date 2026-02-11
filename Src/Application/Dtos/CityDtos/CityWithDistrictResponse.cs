using Application.Dtos.DistrictDtos;

namespace Application.Dtos.CityDtos;

public class CityWithDistrictResponse
{
    public int Id { get; set; }
    public string Name { get; set; } = null!;
    public List<DistrictItemResponse> Districts { get; set; } = new();
}
