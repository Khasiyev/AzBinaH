using Domain.Entities;

namespace Application.Abstracts.Services;

public interface IRefreshTokenService
{
    Task<string> CreateAsync(User user, CancellationToken ct = default);
    Task<User?> ValidateAndConsumeAsync(string token, CancellationToken ct = default);
}
