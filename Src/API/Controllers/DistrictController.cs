using Application.Abstracts.Services;
using Application.Dtos.DistrictDtos;
using Application.Shared.Helpers.Responses;
using Domain.Constants;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers;

[Route("api/[controller]")]
[ApiController]
public class DistrictController : ControllerBase
{
    private readonly IDistrictService _districtService;

    public DistrictController(IDistrictService districtService)
    {
        _districtService = districtService;
    }

    // GET-lər açıq qala bilər
    [HttpGet]
    public async Task<ActionResult<BaseResponse<List<GetAllDistrictResponse>>>> GetAllAsync(CancellationToken ct)
    {
        var district = await _districtService.GetAllDistrictAsync(ct);
        return Ok(BaseResponse<List<GetAllDistrictResponse>>.Ok(district));
    }

    [HttpGet("search")]
    public async Task<ActionResult<BaseResponse<List<GetAllDistrictResponse>>>> GetByNameAsync(
        [FromQuery] string name,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(name))
            return BadRequest(BaseResponse<List<GetAllDistrictResponse>>.Fail("Name cannot be empty"));

        var districts = await _districtService.GetDistrictByNameAsync(name, ct);
        return Ok(BaseResponse<List<GetAllDistrictResponse>>.Ok(districts));
    }

    [HttpGet("{id:int}")]
    public async Task<ActionResult<BaseResponse<GetAllDistrictResponse>>> GetByIdAsync(int id, CancellationToken ct)
    {
        var district = await _districtService.GetDistrictByIdsAsync(id, ct);

        if (district == null)
            return NotFound(BaseResponse<GetAllDistrictResponse>.Fail("District not found"));

        return Ok(BaseResponse<GetAllDistrictResponse>.Ok(district));
    }

    // Create/Update/Delete — yalnız Admin
    [Authorize(Policy = Policies.ManageCities)]
    [HttpPost]
    public async Task<ActionResult<BaseResponse>> CreateAsync(
        [FromBody] CreateDistrictRequest request,
        CancellationToken ct)
    {
        var ok = await _districtService.CreateDistrictAsync(request, ct);

        if (!ok)
            return BadRequest(BaseResponse.Fail("Could not create District"));

        return StatusCode(StatusCodes.Status201Created, BaseResponse.Ok("Created successfully"));
    }

    [Authorize(Policy = Policies.ManageCities)]
    [HttpPut("{id:int}")]
    public async Task<ActionResult<BaseResponse>> UpdateAsync(
        int id,
        [FromBody] UpdateDistrictRequest request,
        CancellationToken ct)
    {
        try
        {
            var ok = await _districtService.UpdateDistrictAsync(id, request, ct);

            if (!ok)
                return NotFound(BaseResponse.Fail("District not found"));

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
        var ok = await _districtService.DeleteDistrictAsync(id, ct);

        if (!ok)
            return NotFound(BaseResponse.Fail("District not found"));

        return Ok(BaseResponse.Ok("Deleted successfully"));
    }
}
