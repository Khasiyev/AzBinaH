using Application.Abstracts.Services;
using Application.Options;
using Microsoft.Extensions.Options;
using Minio;
using Minio.DataModel.Args;

namespace Infrastructure.Services;

public class S3MinioFileStorageService : IFileStorageService
{
    private readonly IMinioClient _minio;
    private readonly MinioOptions _opt;

    public S3MinioFileStorageService(IMinioClient minio, IOptions<MinioOptions> opt)
    {
        _minio = minio;
        _opt = opt.Value;
    }

    public async Task<string> SaveAsync(
        Stream content,
        string fileName,
        string contentType,
        int propertyAdId,
        CancellationToken ct = default)
    {
        var exists = await _minio.BucketExistsAsync(
            new BucketExistsArgs().WithBucket(_opt.Bucket),
            ct);

        if (!exists)
        {
            await _minio.MakeBucketAsync(
                new MakeBucketArgs().WithBucket(_opt.Bucket),
                ct);
        }

        var ext = Path.GetExtension(fileName);
        var objectKey = $"property/{propertyAdId}/{Guid.NewGuid():N}{ext}";

        if (content.CanSeek) content.Position = 0;

        var put = new PutObjectArgs()
            .WithBucket(_opt.Bucket)
            .WithObject(objectKey)
            .WithStreamData(content)
            .WithObjectSize(content.Length)
            .WithContentType(contentType);

        await _minio.PutObjectAsync(put, ct);
        return objectKey;
    }

    public async Task DeleteFileAsync(string objectKey, CancellationToken ct = default)
    {
        await _minio.RemoveObjectAsync(
            new RemoveObjectArgs()
                .WithBucket(_opt.Bucket)
                .WithObject(objectKey),
            ct);
    }
}
