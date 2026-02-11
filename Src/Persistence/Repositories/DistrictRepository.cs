using Application.Abstracts.Repositories;
using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Persistence.Context;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Persistence.Repositories;

public class DistrictRepository:GenericRepository<District,int>,IDistrictRepository
{
    private readonly BinaLiteDbContext _context;
    public DistrictRepository(BinaLiteDbContext context): base(context)
    {
        _context=context;
    }

    public async Task<bool> ExistsByNameDistrictAsync(string name, int excludeId, CancellationToken ct)
    {
        name = name.Trim();

        return await _context.Cities
            .AnyAsync(c =>
                c.Id != excludeId &&
                c.Name.ToLower() == name.ToLower(),
                ct);
    }
}
