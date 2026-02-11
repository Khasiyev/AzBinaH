using Application.Abstracts.Repositories;
using Application.Abstracts.Services;
using Application.Dtos.CityDtos;
using Application.Dtos.DistrictDtos;
using Azure.Core;
using Domain.Entities;
using FluentValidation;
using Microsoft.EntityFrameworkCore;

namespace Persistence.Services;

public class CityService : ICityService
{
    private readonly ICityRepository _cityRepository;
    private readonly IValidator<CreateCityRequest> _createValidator;
    private readonly IValidator<UpdateCityRequest> _updateValidator;

    public CityService(ICityRepository cityRepository,IValidator<CreateCityRequest> createValidator,
        IValidator<UpdateCityRequest> updateValidator)
    {
        _cityRepository = cityRepository;
        _createValidator = createValidator;
        _updateValidator = updateValidator;
    }

    public async Task<bool> CreateCityAsync(CreateCityRequest request, CancellationToken ct = default)
    {
        var exists = await _cityRepository.ExistsByNameAsync(request.Name,0, ct);
        if (exists)
            return false;


        var city = new City
        {
            Name = request.Name,
           
        };

        await _cityRepository.AddAsync(city, ct);
        await _cityRepository.SaveChangesAsync(ct);

        return true;
    }

    public async Task<bool> DeleteCityAsync(int Id, CancellationToken ct = default)
    {
        var city = await _cityRepository.GetByIdAsync(Id, ct);
        if (city is null)
            return false;

        await _cityRepository.DeleteAsync(city, ct);
        await _cityRepository.SaveChangesAsync(ct);

        return true;
    }

  

    public async Task<List<GetAllCitiesResponse>> GetAllCitiesAsync(CancellationToken ct = default)
    {
        var cities = await _cityRepository.GetAllAsync(ct);

        return cities.Select(c => new GetAllCitiesResponse
        {
            Id = c.Id,
            Name = c.Name,
           
        }).ToList();
    }

    public async Task<GetAllCitiesResponse> GetCitiesByIdsAsync(int Id,
    CancellationToken ct = default)
    {
        var cities = await _cityRepository.GetAllAsync(ct);

        var city = cities.FirstOrDefault(c => c.Id == Id);
        if (city == null)
            return null;

        return new GetAllCitiesResponse
        {
            Id = city.Id,
            Name = city.Name,
           
        };
    }
    public async Task<List<GetAllCitiesResponse>> GetCitiesByNameAsync(string name, CancellationToken ct = default)
    {
        if (name == null)
            throw new ArgumentNullException(nameof(name));

        name = name.Trim().ToLower();
        if (name.Length == 0)
            return new List<GetAllCitiesResponse>();

        var cities = await _cityRepository.GetAllAsync(ct);

        return cities
            .Where(c =>
                !string.IsNullOrEmpty(c.Name) &&
                c.Name.Trim().ToLower().Contains(name))
            .Select(c => new GetAllCitiesResponse
            {
                Id = c.Id,
                Name = c.Name,
               
            })
            .ToList();
    }

    public async Task<bool> UpdateCityAsync(int Id, UpdateCityRequest request, CancellationToken ct = default)
    {
        var city = await _cityRepository.GetByIdAsync(Id, ct);
        if (city is null)
            return false;

        var name = (request.Name ?? "").Trim();
        if (name.Length == 0)
            throw new InvalidOperationException("City Name cannot be empty");

        var exists = await _cityRepository.ExistsByNameAsync(name, Id, ct);
        if (exists)
            throw new InvalidOperationException("This city name already exists.");

        city.Name = name;
        city.UpdatedAt = DateTime.UtcNow;

        await _cityRepository.UpdateAsync(city, ct);
        await _cityRepository.SaveChangesAsync(ct);

        return true;
    }
    public async Task<bool> ExistsByNameAsync(string name, CancellationToken ct = default)
{
    name = (name ?? "").Trim();
    if (name.Length == 0)
        return false;

    return await _cityRepository.ExistsByNameAsync(name, 0, ct);
}
    public async Task<List<CityWithDistrictResponse>> GetCityWithDistrictsAsync(CancellationToken ct = default)
    {
        var cities = await _cityRepository.GetAllWithDistrictsAsync(ct);

        return cities.Select(c => new CityWithDistrictResponse
        {
            Id = c.Id,
            Name = c.Name,
            Districts = c.Districts.Select(d => new DistrictItemResponse
            {
                Id = d.Id,
                Name = d.Name
            }).ToList()
        }).ToList();
    }
}



