using Application.Abstracts.Repositories;
using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Persistence.Context;

namespace Persistence.Services;

public class FileService : IFileService
{
    private readonly BinaLiteDbContext _context;
    public FileService(BinaLiteDbContext context)
    {
        _context = context;
    }
    public async Task<int> UploadAsync(
         byte[] content,
         string fileName,
         string contentType
     )
    {
        var entity = new AppFile
        {
            FileName = fileName,
            ContentType = contentType,
            Content = content
        };

        _context.Files.Add(entity);
        await _context.SaveChangesAsync();

        return entity.Id;
    }

    public async Task<List<AppFile>> GetAllAsync()
    {
        return await _context.Files
            .Select(x => new AppFile
            {
                Id = x.Id,
                FileName = x.FileName,
                ContentType = x.ContentType
                // Content QAYTARMIQ
            })
            .ToListAsync();
    }

    public async Task<AppFile?> GetByIdAsync(int id)
    {
        return await _context.Files.FirstOrDefaultAsync(x => x.Id == id);
    }
}
