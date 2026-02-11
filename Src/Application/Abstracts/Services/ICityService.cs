using Application.Dtos.CityDtos;

namespace Application.Abstracts.Services;

public interface ICityService
{
    Task<bool> CreateCityAsync(CreateCityRequest request, CancellationToken ct = default);
    Task<List<GetAllCitiesResponse>> GetAllCitiesAsync(CancellationToken ct = default);
    Task<bool> DeleteCityAsync(int Id, CancellationToken ct = default);
    Task<bool> UpdateCityAsync(int Id, UpdateCityRequest request, CancellationToken ct = default);
    Task<List<GetAllCitiesResponse>> GetCitiesByNameAsync(string name, CancellationToken ct = default);
    Task<GetAllCitiesResponse> GetCitiesByIdsAsync(int Id, CancellationToken ct = default);
    Task<bool> ExistsByNameAsync(string name, CancellationToken ct = default);
    Task<List<CityWithDistrictResponse>> GetCityWithDistrictsAsync(CancellationToken ct = default);
}
