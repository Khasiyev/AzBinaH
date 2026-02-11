using Domain.Entities;

namespace Application.Abstracts.Repositories;

public interface IRepository<TEntity,TKey> where TEntity : BaseEntity<TKey>
{
    Task<List<TEntity>> GetAllAsync(CancellationToken ct = default);

    Task<TEntity> GetByIdAsync(TKey id, CancellationToken ct = default);

    Task AddAsync(TEntity entity, CancellationToken ct = default);

    Task UpdateAsync(TEntity entity, CancellationToken ct = default);

    Task DeleteAsync(TEntity entity, CancellationToken ct = default);

    Task<int> SaveChangesAsync(CancellationToken ct = default);

}
