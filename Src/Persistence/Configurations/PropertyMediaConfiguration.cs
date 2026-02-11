using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Persistence.Configurations;

internal class PropertyMediaConfiguration : IEntityTypeConfiguration<PropertyMedia>
{
    public void Configure(EntityTypeBuilder<PropertyMedia> builder)
    {
        builder.ToTable("PropertyMedias");

        builder.HasKey(x => x.Id);

        builder.Property(x => x.ObjectKey)
            .IsRequired()
            .HasMaxLength(500);

        builder.Property(x => x.Order)
            .IsRequired()
            .HasDefaultValue(0);

        builder.Property(x => x.PropertyAdId)
            .IsRequired();

        builder.HasOne(x => x.PropertyAd)
            .WithMany(p => p.MediaItems)
            .HasForeignKey(x => x.PropertyAdId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasIndex(x => x.PropertyAdId);
        builder.HasIndex(x => new { x.PropertyAdId, x.Order });
    }
}
