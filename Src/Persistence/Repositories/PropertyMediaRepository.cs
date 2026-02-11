using Application.Abstracts.Repositories;
using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Persistence.Context;

namespace Persistence.Repositories;

public class PropertyMediaRepository
    : GenericRepository<PropertyMedia, int>, IPropertyMediaRepository
{
    private readonly DbSet<PropertyMedia> _table;

    public PropertyMediaRepository(BinaLiteDbContext context) : base(context)
    {
        _table = context.Set<PropertyMedia>();
    }

    public async Task<List<PropertyMedia>> GetByPropertyAdIdAsync(int propertyAdId, CancellationToken ct = default)
    {
        return await _table
            .Where(x => x.PropertyAdId == propertyAdId)
            .OrderBy(x => x.Order)
            .ToListAsync(ct);
    }
}