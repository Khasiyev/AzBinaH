using Application.Dtos.AuthDtos;

namespace Application.Abstracts.Services;

public interface IAuthService
{
    Task<(bool Success, string? Error)> RegisterAsync(RegisterRequest request, CancellationToken ct = default);
    Task<string?> LoginAsync(LoginRequest request, CancellationToken ct = default);
}
