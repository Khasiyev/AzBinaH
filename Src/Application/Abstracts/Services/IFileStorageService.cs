namespace Application.Abstracts.Services;

public interface IFileStorageService
{
    Task<string> SaveAsync(Stream content, string fileName, string contentType, int propertyAdId, CancellationToken ct = default);
    Task DeleteFileAsync(string objectKey, CancellationToken ct = default);
}
