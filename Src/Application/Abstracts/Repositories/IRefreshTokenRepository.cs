using Domain.Entities;

namespace Application.Abstracts.Repositories;

public interface IRefreshTokenRepository
{
    Task<RefreshToken?> GetByTokenWithUserAsync(string token, CancellationToken ct = default);
    Task AddAsync(RefreshToken refreshToken, CancellationToken ct = default);
    Task DeleteByTokenAsync(string token, CancellationToken ct = default);
}
