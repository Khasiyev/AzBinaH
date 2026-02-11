using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Persistence.Configurations;

public class PropertyAdConfiguration : IEntityTypeConfiguration<PropertyAd>
{
    public void Configure(EntityTypeBuilder<PropertyAd> builder)
    {
        builder.ToTable("PropertyAd");

        builder.HasKey(x => x.Id);

        builder.Property(x => x.Title)
            .IsRequired()
            .HasMaxLength(150);

        builder.Property(x => x.Description)
            .IsRequired()
            .HasMaxLength(4000);

        builder.Property(x => x.Price)
            .IsRequired()
            .HasColumnType("decimal(18,2)");

  
        builder.Property(x => x.IsNew).IsRequired();
        builder.Property(x => x.IsRenovated).IsRequired();
        builder.Property(x => x.IsMortgage).IsRequired();
        builder.Property(x => x.IsTitleDeedAvailable).IsRequired();


        builder.Property(x => x.RoomCount)
            .IsRequired();

        builder.Property(x => x.AreaInSquareMeters)
            .IsRequired()
            .HasColumnType("decimal(10,2)");

       
        builder.Property(x => x.Location)
            .IsRequired()
            .HasMaxLength(300);

        builder.Property(x => x.FloorNumber)
            .IsRequired();

     
        builder.Property(x => x.PropertyCategory)
            .IsRequired()
            .HasConversion<int>();

        builder.Property(x => x.OfferType)
            .IsRequired()
            .HasConversion<int>();

        builder.HasIndex(x => x.OfferType);
        builder.HasIndex(x => x.PropertyCategory);
        builder.HasIndex(x => x.Price);
        builder.HasIndex(x => x.RoomCount);
    }
}
