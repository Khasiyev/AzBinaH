using Application.Abstracts.Repositories;
using Application.Abstracts.Services;
using Application.Options;
using Domain.Entities;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;

namespace Persistence.Services;

public class RefreshTokenService : IRefreshTokenService
{
    private readonly IRefreshTokenRepository _refreshRepo;
    private readonly JwtOptions _jwt;

    public RefreshTokenService(
        IRefreshTokenRepository refreshRepo,
        IOptions<JwtOptions> jwtOptions)
    {
        _refreshRepo = refreshRepo;
        _jwt = jwtOptions.Value;
    }

    public async Task<string> CreateAsync(User user, CancellationToken ct = default)
    {
        var token = GenerateSecureHexToken(byteCount: 32);

        var refreshEntity = new RefreshToken
        {
            Token = token,
            UserId = user.Id,
            CreatedAtUtc = DateTime.UtcNow,
            ExpiresAtUtc = DateTime.UtcNow.AddMinutes(_jwt.RefreshExpirationMinutes)
        };

        await _refreshRepo.AddAsync(refreshEntity, ct);
        return token;
    }

    public async Task<User?> ValidateAndConsumeAsync(string token, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(token))
            return null;

        var refresh = await _refreshRepo.GetByTokenWithUserAsync(token, ct);
        if (refresh is null)
            return null;

        if (refresh.ExpiresAtUtc <= DateTime.UtcNow)
            return null;

        await _refreshRepo.DeleteByTokenAsync(token, ct);

        return refresh.User;
    }

    private static string GenerateSecureHexToken(int byteCount)
    {
        var bytes = RandomNumberGenerator.GetBytes(byteCount);
        return Convert.ToHexString(bytes);
    }
}
