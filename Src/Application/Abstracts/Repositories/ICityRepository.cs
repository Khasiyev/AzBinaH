using Domain.Entities;

namespace Application.Abstracts.Repositories;

public interface ICityRepository:IRepository<City,int>
{
    Task<bool> ExistsByNameAsync(string name, int excludeId, CancellationToken ct);
    Task<List<City>> GetAllWithDistrictsAsync(CancellationToken ct);
}
