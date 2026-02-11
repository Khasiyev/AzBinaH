using Application.Abstracts.Repositories;
using Application.Abstracts.Services;
using Application.Dtos.PropertyAdDtos;
using Application.Validations.PropertyAdValidation;
using AutoMapper;
using Domain.Entities;
using FluentValidation;

namespace Persistence.Services;

public class PropertyAdService : IPropertyAdService
{
    private readonly IPropertyAdRepository _repository;
    private readonly IPropertyMediaRepository _mediaRepository;
    private readonly IFileStorageService _fileStorage;

    private readonly IMapper _mapper;
    private readonly IValidator<CreatePropertyAdRequest> _createValidator;
    private readonly IValidator<UpdatePropertyAdRequest> _updateValidator;

    public PropertyAdService(
        IPropertyAdRepository repository,
        IPropertyMediaRepository mediaRepository,
        IFileStorageService fileStorage,
        IMapper mapper,
        IValidator<CreatePropertyAdRequest> createvalidator,
        IValidator<UpdatePropertyAdRequest> updatevalidator)
    {
        _repository = repository;
        _mediaRepository = mediaRepository;
        _fileStorage = fileStorage;

        _mapper = mapper;
        _createValidator = createvalidator;
        _updateValidator = updatevalidator;
    }

    public async Task<bool> CreatePropertyAdAsync(CreatePropertyAdRequest request, CancellationToken ct = default)
    {
        await _createValidator.ValidateAndThrowAsync(request, cancellationToken: ct);

        var entity = _mapper.Map<PropertyAd>(request);
        await _repository.AddAsync(entity, ct);

        var affected = await _repository.SaveChangesAsync(ct);
        if (affected <= 0) return false;

        if (request.Media != null && request.Media.Count > 0)
        {
            foreach (var m in request.Media.OrderBy(x => x.Order))
            {
                var objectKey = await _fileStorage.SaveAsync(
                    m.Content,
                    m.FileName,
                    m.ContentType,
                    entity.Id,
                    ct);

                await _mediaRepository.AddAsync(new PropertyMedia
                {
                    PropertyAdId = entity.Id,
                    ObjectKey = objectKey,
                    Order = m.Order
                }, ct);
            }

            affected = await _repository.SaveChangesAsync(ct);
            return affected > 0;
        }

        return true;
    }

    public async Task<bool> UpdatePropertyAdAsync(int id, UpdatePropertyAdRequest request, CancellationToken ct = default)
    {
        await _updateValidator.ValidateAndThrowAsync(request, cancellationToken: ct);

        if (request.Id != 0 && request.Id != id)
            return false;

        var entity = await _repository.GetByIdAsync(id, ct);
        if (entity == null)
            return false;

        _mapper.Map(request, entity);

        if (request.RemoveMediaIds != null && request.RemoveMediaIds.Length > 0)
        {
            foreach (var mediaId in request.RemoveMediaIds)
            {
                var media = await _mediaRepository.GetByIdAsync(mediaId, ct);
                if (media == null) continue;

                await _fileStorage.DeleteFileAsync(media.ObjectKey, ct);

                await _mediaRepository.DeleteAsync(media, ct);
            }
        }

        if (request.AddMedia != null && request.AddMedia.Count > 0)
        {
            foreach (var m in request.AddMedia.OrderBy(x => x.Order))
            {
                var objectKey = await _fileStorage.SaveAsync(
                    m.Content,
                    m.FileName,
                    m.ContentType,
                    id,
                    ct);

                await _mediaRepository.AddAsync(new PropertyMedia
                {
                    PropertyAdId = id,
                    ObjectKey = objectKey,
                    Order = m.Order
                }, ct);
            }
        }

        var affected = await _repository.SaveChangesAsync(ct);
        return affected > 0;
    }

    public async Task<bool> DeletePropertyAdAsync(int id, CancellationToken ct = default)
    {
        var entity = await _repository.GetByIdAsync(id, ct);
        if (entity == null)
            return false;

        var medias = await _mediaRepository.GetByPropertyAdIdAsync(id, ct);

        foreach (var media in medias)
        {
            await _fileStorage.DeleteFileAsync(media.ObjectKey, ct);
        }

        await _repository.DeleteAsync(entity, ct);

        var affected = await _repository.SaveChangesAsync(ct);
        return affected > 0;
    }

    public async Task<List<GetAllPropertyAdResponse>> GetAllAsync(CancellationToken ct = default)
    {
        var entities = await _repository.GetAllAsync(ct);
        return _mapper.Map<List<GetAllPropertyAdResponse>>(entities);
    }

    public async Task<GetByIdPropertyAdResponse?> GetByIdAsync(int id, CancellationToken ct = default)
    {
        var entity = await _repository.GetByIdAsync(id, ct);
        return entity is null ? null : _mapper.Map<GetByIdPropertyAdResponse>(entity);
    }
}
