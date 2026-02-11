namespace Application.Dtos.PropertyAdDtos;

public class MediaUploadInput
{
    public Stream Content { get; set; } = default!;
    public string FileName { get; set; } = default!;
    public string ContentType { get; set; } = default!;
    public int Order { get; set; }
}
