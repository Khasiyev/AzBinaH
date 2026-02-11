namespace Domain.Entities;

public class PropertyMedia: BaseEntity<int>
{
    public string ObjectKey { get; set; } = default!;
    public int Order { get; set; }
    public int PropertyAdId { get; set; }
    public PropertyAd PropertyAd { get; set; } = default!;
}
