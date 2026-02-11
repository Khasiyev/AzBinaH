namespace Domain.Entities;

public class City:BaseEntity<int>
{
    public string Name { get; set; } = null!;
    public ICollection<District> Districts { get; set; } = new List<District>();

}
