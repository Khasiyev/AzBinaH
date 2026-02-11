using Domain.Enums;

namespace Application.Dtos.PropertyAdDtos;

public class GetByIdPropertyAdResponse
{
    public int Id { get; set; }
    public string Title { get; set; } = null!;
    public string? Description { get; set; }
    public decimal Price { get; set; }
    public bool IsNew { get; set; }
    public bool IsRenovated { get; set; }
    public bool IsMortgage { get; set; }
    public bool IsTitleDeedAvailable { get; set; }
    public int RoomCount { get; set; }
    public double AreaInSquareMeters { get; set; }
    public string Location { get; set; } = null!;
    public int FloorNumber { get; set; }
    public int TotalFloors { get; set; }
    public PropertyCategory PropertyCategory { get; set; }
    public OfferType OfferType { get; set; }
    public List<PropertyMediaItemDto> Media { get; set; } = new();

}
