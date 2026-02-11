using Application.Abstracts.Repositories;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers;

[Route("api/[controller]")]
[ApiController]
public class FileController : ControllerBase
{
    private readonly IFileService _fileService;

    public FileController(IFileService fileService)
    {
        _fileService = fileService;
    }
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        return Ok(await _fileService.GetAllAsync());
    }

    // DOWNLOAD
    [HttpGet("{id}")]
    public async Task<IActionResult> Download(int id)
    {
        var file = await _fileService.GetByIdAsync(id);
        if (file == null)
            return NotFound();

        return File(file.Content, file.ContentType, file.FileName);
    }
    [HttpPost]
    [Consumes("multipart/form-data")]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        if (file == null || file.Length == 0)
            return BadRequest("File gelmedi / bosdur");

        var contentType = string.IsNullOrWhiteSpace(file.ContentType)
            ? "application/octet-stream"
            : file.ContentType;

        using var ms = new MemoryStream();
        await file.CopyToAsync(ms);

        var id = await _fileService.UploadAsync(
            ms.ToArray(),
            file.FileName,
            contentType
        );

        return Ok(id);
    }
}
