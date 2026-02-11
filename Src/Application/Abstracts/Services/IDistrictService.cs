using Application.Dtos.CityDtos;
using Application.Dtos.DistrictDtos;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Abstracts.Services;

public interface IDistrictService
{
    Task<bool> CreateDistrictAsync(CreateDistrictRequest request, CancellationToken ct = default);
    Task<List<GetAllDistrictResponse>> GetAllDistrictAsync(CancellationToken ct = default);
    Task<bool> DeleteDistrictAsync(int Id, CancellationToken ct = default);
    Task<bool> UpdateDistrictAsync(int Id, UpdateDistrictRequest request, CancellationToken ct = default);
    Task<List<GetAllDistrictResponse>> GetDistrictByNameAsync(string name, CancellationToken ct = default);
    Task<GetAllDistrictResponse> GetDistrictByIdsAsync(int Id, CancellationToken ct = default);
    Task<bool> ExistsByNameDistrictAsync(string name, CancellationToken ct = default);
    
}
