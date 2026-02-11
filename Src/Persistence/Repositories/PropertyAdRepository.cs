using Application.Abstracts.Repositories;
using Domain.Entities;
using Persistence.Context;

namespace Persistence.Repositories;

public class PropertyAdRepository : GenericRepository<PropertyAd, int>,IPropertyAdRepository
{
    public PropertyAdRepository(BinaLiteDbContext context) : base(context)
    {

    }
}
