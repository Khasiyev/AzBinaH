using Application.Abstracts.Repositories;
using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Persistence.Context;

namespace Persistence.Repositories;

public class CityRepository:GenericRepository<City,int>,ICityRepository
{
    private readonly BinaLiteDbContext _context;
    public CityRepository(BinaLiteDbContext context) : base(context)
    {
        _context = context;
    }
    public async Task<bool> ExistsByNameAsync(string name, int excludeId, CancellationToken ct)
    {
        name = name.Trim();

        return await _context.Cities
            .AnyAsync(c =>
                c.Id != excludeId &&
                c.Name.ToLower() == name.ToLower(),
                ct);
    }
    public async Task<List<City>> GetAllWithDistrictsAsync(CancellationToken ct)
    {
        return await _context.Cities
            .Include(c => c.Districts)
            .ToListAsync(ct);
    }
}
