namespace Application.Dtos.AuthDtos;

public class TokenResponse
{
    public string AccessToken { get; set; } = null!;
    public string RefreshToken { get; set; } = null!;
    public DateTime ExpiresAtUtc { get; set; }
}
