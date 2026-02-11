using Application.Abstracts.Repositories;
using Application.Abstracts.Services;
using Application.Dtos.PropertyAdDtos;
using Application.Shared.Helpers.Responses;
using AutoMapper;
using Domain.Entities;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers;

[Route("api/[controller]")]
[ApiController]
public class PropertyAdController : ControllerBase
{
    private readonly IPropertyAdService _propertyAdService;
    private readonly IPropertyMediaRepository _propertyMediaRepository;
    private readonly IFileStorageService _fileStorage;
    private readonly IMapper _mapper;

    public PropertyAdController(
        IPropertyAdService propertyAdService,
        IPropertyMediaRepository propertyMediaRepository,
        IFileStorageService fileStorage,
        IMapper mapper)
    {
        _propertyAdService = propertyAdService;
        _propertyMediaRepository = propertyMediaRepository;
        _fileStorage = fileStorage;
        _mapper = mapper;
    }

    [HttpGet]
    public async Task<ActionResult<BaseResponse<List<GetAllPropertyAdResponse>>>> GetAllAsync(CancellationToken ct)
    {
        var propertyAds = await _propertyAdService.GetAllAsync(ct);
        return Ok(BaseResponse<List<GetAllPropertyAdResponse>>.Ok(propertyAds));
    }

    [HttpGet("{id:int}")]
    public async Task<ActionResult<BaseResponse<GetByIdPropertyAdResponse>>> GetByIdAsync(int id, CancellationToken ct)
    {
        var propertyAd = await _propertyAdService.GetByIdAsync(id, ct);
        if (propertyAd is null)
            return NotFound(BaseResponse<GetByIdPropertyAdResponse>.Fail("PropertyAd not found"));

        return Ok(BaseResponse<GetByIdPropertyAdResponse>.Ok(propertyAd));
    }

    //Create
    [HttpPost]
    [Consumes("multipart/form-data")]
    public async Task<ActionResult<BaseResponse>> CreateAsync(
        [FromForm] CreatePropertyAdRequest request,
        [FromForm] IFormFileCollection? media,
        CancellationToken ct)
    {
        var streams = new List<Stream>();

        try
        {
            if (media != null && media.Count > 0)
            {
                request.Media ??= new List<MediaUploadInput>();

                var order = 0;
                foreach (var file in media)
                {
                    var stream = file.OpenReadStream();
                    streams.Add(stream);

                    request.Media.Add(new MediaUploadInput
                    {
                        Content = stream,
                        FileName = file.FileName,
                        ContentType = file.ContentType,
                        Order = order++
                    });
                }
            }

            var ok = await _propertyAdService.CreatePropertyAdAsync(request, ct);
            if (!ok) return BadRequest(BaseResponse.Fail("Could not create PropertyAd"));

            return Ok(BaseResponse.Ok("Created successfully"));
        }
        finally
        {
            foreach (var s in streams) s.Dispose();
        }
    }

    //Update
    [HttpPut("{id:int}")]
    [Consumes("multipart/form-data")]
    public async Task<ActionResult<BaseResponse>> UpdateAsync(
        int id,
        [FromForm] UpdatePropertyAdRequest request,
        [FromForm] IFormFileCollection? addMedia,
        [FromForm] int[]? removeMediaIds,
        CancellationToken ct)
    {
        var streams = new List<Stream>();

        try
        {
            request.RemoveMediaIds = removeMediaIds;

            if (addMedia != null && addMedia.Count > 0)
            {
                request.AddMedia ??= new List<MediaUploadInput>();

                var order = 0;
                foreach (var file in addMedia)
                {
                    var stream = file.OpenReadStream();
                    streams.Add(stream);

                    request.AddMedia.Add(new MediaUploadInput
                    {
                        Content = stream,
                        FileName = file.FileName,
                        ContentType = file.ContentType,
                        Order = order++
                    });
                }
            }

            var ok = await _propertyAdService.UpdatePropertyAdAsync(id, request, ct);

            if (!ok)
                return NotFound(BaseResponse.Fail("PropertyAd not found"));

            return Ok(BaseResponse.Ok("Updated successfully"));
        }
        finally
        {
            foreach (var s in streams) s.Dispose();
        }
    }

    [HttpDelete("{id:int}")]
    public async Task<ActionResult<BaseResponse>> DeleteAsync(int id, CancellationToken ct)
    {
        var ok = await _propertyAdService.DeletePropertyAdAsync(id, ct);

        if (!ok)
            return NotFound(BaseResponse.Fail("PropertyAd not found"));

        return Ok(BaseResponse.Ok("Deleted successfully"));
    }

    //POST: media (tək fayl)
    [HttpPost("{propertyId:int}/media")]
    [Consumes("multipart/form-data")]
    public async Task<IActionResult> UploadSingleMedia(int propertyId, IFormFile file, CancellationToken ct)
    {
        var current = await _propertyMediaRepository.GetByPropertyAdIdAsync(propertyId, ct);
        if (current.Count >= 5)
            return BadRequest(BaseResponse.Fail("Maximum 5 media allowed"));

        await using var stream = file.OpenReadStream();

        var objectKey = await _fileStorage.SaveAsync(
            stream,
            file.FileName,
            file.ContentType,
            propertyId,
            ct);

        var nextOrder = current.Count == 0 ? 0 : current.Max(x => x.Order) + 1;

        await _propertyMediaRepository.AddAsync(new PropertyMedia
        {
            PropertyAdId = propertyId,
            ObjectKey = objectKey,
            Order = nextOrder
        }, ct);

        await _propertyMediaRepository.SaveChangesAsync(ct);

        return Ok(BaseResponse<string>.Ok(objectKey));
    }

    //GET: media
    [HttpGet("{propertyId:int}/media")]
    public async Task<ActionResult<BaseResponse<List<PropertyMediaItemDto>>>> GetMedia(int propertyId, CancellationToken ct)
    {
        var medias = await _propertyMediaRepository.GetByPropertyAdIdAsync(propertyId, ct);
        var dto = _mapper.Map<List<PropertyMediaItemDto>>(medias);
        return Ok(BaseResponse<List<PropertyMediaItemDto>>.Ok(dto));
    }

    //DELETE: media{id}
    [HttpDelete("media/{id:int}")]
    public async Task<IActionResult> DeleteMedia(int id, CancellationToken ct)
    {
        var media = await _propertyMediaRepository.GetByIdAsync(id, ct);
        if (media == null)
            return NotFound(BaseResponse.Fail("Media not found"));

        await _fileStorage.DeleteFileAsync(media.ObjectKey, ct);

        await _propertyMediaRepository.DeleteAsync(media, ct);
        await _propertyMediaRepository.SaveChangesAsync(ct);

        return NoContent();
    }
}
