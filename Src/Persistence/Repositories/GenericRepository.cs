

using Application.Abstracts.Repositories;
using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Persistence.Context;
using System.Collections.Generic;

namespace Persistence.Repositories;

public class GenericRepository<TEntity, TKey> : IRepository<TEntity, TKey>
    where TEntity : BaseEntity<TKey>
{
    private readonly BinaLiteDbContext _context;
    private readonly DbSet<TEntity> _table;
    public GenericRepository(BinaLiteDbContext context)
    {
        _context = context;
        _table= _context.Set<TEntity>();
    }
    public async Task<List<TEntity>> GetAllAsync(CancellationToken ct = default)
    {
       return await _table.ToListAsync(ct);
    }

    public async Task<TEntity?> GetByIdAsync(TKey Id, CancellationToken ct = default)
    { 
        return await _table.FindAsync( Id , ct);
    }

    public async Task AddAsync(TEntity entity, CancellationToken ct = default)
    {
        await _context.AddAsync(entity, ct).AsTask();
    }

    public Task UpdateAsync(TEntity entity, CancellationToken ct = default)
    {
        _context.Update(entity);               
        return Task.CompletedTask;
    }

    public Task DeleteAsync(TEntity entity, CancellationToken ct = default)
    {
        _context.Remove(entity);              
        return Task.CompletedTask;
    }

    public  Task<int> SaveChangesAsync(CancellationToken ct = default)
    {
       return  _context.SaveChangesAsync(ct);
    }
}
