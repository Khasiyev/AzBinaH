using Application.Dtos.AuthDtos;

namespace Application.Abstracts.Services;

public interface IAuthService
{
    Task<(bool Success, string? Error)> RegisterAsync(RegisterRequest request, CancellationToken ct = default);

    Task<TokenResponse?> LoginAsync(LoginRequest request, CancellationToken ct = default);

    Task<TokenResponse?> RefreshTokenAsync(string refreshToken, CancellationToken ct = default);
}
