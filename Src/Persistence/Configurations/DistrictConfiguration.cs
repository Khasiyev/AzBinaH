using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Persistence.Configurations;

public class DistrictConfiguration : IEntityTypeConfiguration<District>
{
    public void Configure(EntityTypeBuilder<District> builder)
    {
        builder.ToTable("District");
        builder.HasKey(d => d.Id);
        builder.Property(d => d.Name)
            .IsRequired()
            .HasMaxLength(100);
        builder.HasIndex(d => new { d.Name, d.CityId })
            .IsUnique();
        builder.HasOne(d => d.City)
            .WithMany(c => c.Districts)
            .HasForeignKey(d => d.CityId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
