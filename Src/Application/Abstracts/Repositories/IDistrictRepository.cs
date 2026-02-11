using Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Abstracts.Repositories;

public interface IDistrictRepository:IRepository<District,int>
{
    Task<bool> ExistsByNameDistrictAsync(string name, int excludeId, CancellationToken ct);
}
