using Domain.Entities;

namespace Application.Abstracts.Repositories;

public interface IFileService
{
    Task<int> UploadAsync( byte[] content, string fileName,string contentType );
    Task<List<AppFile>> GetAllAsync();
    Task<AppFile?> GetByIdAsync(int id);
}
