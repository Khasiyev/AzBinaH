using Domain.Entities;

namespace Application.Abstracts.Repositories;

public interface IPropertyMediaRepository: IRepository<PropertyMedia, int>
{
    Task<List<PropertyMedia>> GetByPropertyAdIdAsync(int propertyAdId, CancellationToken ct = default);
}
