using Application.Abstracts.Repositories;
using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Persistence.Context;

namespace Persistence.Repositories;

public class RefreshTokenRepository : IRefreshTokenRepository
{
    private readonly BinaLiteDbContext _db;

    public RefreshTokenRepository(BinaLiteDbContext db)
    {
        _db = db;
    }

    public Task<RefreshToken?> GetByTokenWithUserAsync(string token, CancellationToken ct = default)
    {
        return _db.RefreshTokens
            .Include(x => x.User)
            .FirstOrDefaultAsync(x => x.Token == token, ct);
    }

    public async Task AddAsync(RefreshToken refreshToken, CancellationToken ct = default)
    {
        await _db.RefreshTokens.AddAsync(refreshToken, ct);
        await _db.SaveChangesAsync(ct);
    }

    public async Task DeleteByTokenAsync(string token, CancellationToken ct = default)
    {
        await _db.RefreshTokens
            .Where(x => x.Token == token)
            .ExecuteDeleteAsync(ct);
    }
}
