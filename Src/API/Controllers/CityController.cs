using Domain.Constants;
using Application.Abstracts.Services;
using Application.Dtos.CityDtos;
using Application.Shared.Helpers.Responses;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers;

[Route("api/[controller]")]
[ApiController]
public class CityController : ControllerBase
{
    private readonly ICityService _cityService;

    public CityController(ICityService cityService)
    {
        _cityService = cityService;
    }

    // ✅ GET-lər açıq qala bilər
    [HttpGet("with-districts")]
    public async Task<ActionResult<BaseResponse<List<CityWithDistrictResponse>>>> GetWithDistricts(CancellationToken ct)
    {
        var result = await _cityService.GetCityWithDistrictsAsync(ct);
        return Ok(result);
    }

    [HttpGet]
    public async Task<ActionResult<BaseResponse<List<GetAllCitiesResponse>>>> GetAllAsync(CancellationToken ct)
    {
        var cities = await _cityService.GetAllCitiesAsync(ct);
        return Ok(BaseResponse<List<GetAllCitiesResponse>>.Ok(cities));
    }

    [HttpGet("search")]
    public async Task<ActionResult<BaseResponse<List<GetAllCitiesResponse>>>> GetByNameAsync(
        [FromQuery] string name,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(name))
            return BadRequest(BaseResponse<List<GetAllCitiesResponse>>.Fail("Name cannot be empty"));

        var cities = await _cityService.GetCitiesByNameAsync(name, ct);
        return Ok(BaseResponse<List<GetAllCitiesResponse>>.Ok(cities));
    }

    [HttpGet("{id:int}")]
    public async Task<ActionResult<BaseResponse<GetAllCitiesResponse>>> GetByIdAsync(int id, CancellationToken ct)
    {
        var city = await _cityService.GetCitiesByIdsAsync(id, ct);

        if (city == null)
            return NotFound(BaseResponse<GetAllCitiesResponse>.Fail("City not found"));

        return Ok(BaseResponse<GetAllCitiesResponse>.Ok(city));
    }

    // ✅ Create/Update/Delete — yalnız Admin
    [Authorize(Policy = Policies.ManageCities)]
    [HttpPost]
    public async Task<ActionResult<BaseResponse>> CreateAsync([FromBody] CreateCityRequest request, CancellationToken ct)
    {
        var ok = await _cityService.CreateCityAsync(request, ct);

        if (!ok)
            return BadRequest(BaseResponse.Fail("Could not create City"));

        return StatusCode(StatusCodes.Status201Created, BaseResponse.Ok("Created successfully"));
    }

    [Authorize(Policy = Policies.ManageCities)]
    [HttpPut("{id:int}")]
    public async Task<ActionResult<BaseResponse>> UpdateAsync(int id, [FromBody] UpdateCityRequest request, CancellationToken ct)
    {
        try
        {
            var ok = await _cityService.UpdateCityAsync(id, request, ct);

            if (!ok)
                return NotFound(BaseResponse.Fail("City not found"));

            return Ok(BaseResponse.Ok("Updated successfully"));
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(BaseResponse.Fail(ex.Message));
        }
    }

    [Authorize(Policy = Policies.ManageCities)]
    [HttpDelete("{id:int}")]
    public async Task<ActionResult<BaseResponse>> DeleteAsync(int id, CancellationToken ct)
    {
        var ok = await _cityService.DeleteCityAsync(id, ct);

        if (!ok)
            return NotFound(BaseResponse.Fail("City not found"));

        return Ok(BaseResponse.Ok("Deleted successfully"));
    }
}
