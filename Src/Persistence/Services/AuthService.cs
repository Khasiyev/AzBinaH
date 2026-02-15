using Application.Abstracts.Services;
using Application.Dtos.AuthDtos;
using Application.Options;
using Domain.Constants;
using Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Persistence.Services;

public class AuthService : IAuthService
{
    private readonly UserManager<User> _userManager;
    private readonly SignInManager<User> _signInManager;
    private readonly IJwtTokenGenerator _jwtGenerator;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly JwtOptions _jwtOpt;

    public AuthService(
        UserManager<User> userManager,
        SignInManager<User> signInManager,
        IJwtTokenGenerator jwtGenerator,
        IRefreshTokenService refreshTokenService,
        IOptions<JwtOptions> jwtOptions)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _jwtGenerator = jwtGenerator;
        _refreshTokenService = refreshTokenService;
        _jwtOpt = jwtOptions.Value;
    }

    // ✅ RegisterAsync: User yarat + RoleNames.User ver
    public async Task<(bool Success, string? Error)> RegisterAsync(
        RegisterRequest request,
        CancellationToken ct = default)
    {
        var user = new User
        {
            UserName = request.UserName,    // istəsən: request.Email
            Email = request.Email,
            FullName = request.FullName,
            EmailConfirmed = true
        };

        var result = await _userManager.CreateAsync(user, request.Password);

        if (!result.Succeeded)
        {
            var error = string.Join("; ", result.Errors.Select(e => e.Description));
            return (false, error);
        }

        var roleRes = await _userManager.AddToRoleAsync(user, RoleNames.User);
        if (!roleRes.Succeeded)
        {
            var error = string.Join("; ", roleRes.Errors.Select(e => e.Description));
            return (false, error);
        }

        return (true, null);
    }

    // ✅ LoginAsync: FindByEmail/FindByName + CheckPasswordSignInAsync + BuildTokenResponseAsync
    public async Task<TokenResponse?> LoginAsync(LoginRequest request, CancellationToken ct = default)
    {
        var user =
            await _userManager.FindByEmailAsync(request.Login)
            ?? await _userManager.FindByNameAsync(request.Login);

        if (user is null)
            return null;

        var signInResult = await _signInManager.CheckPasswordSignInAsync(
            user,
            request.Password,
            lockoutOnFailure: false);

        if (!signInResult.Succeeded)
            return null;

        return await BuildTokenResponseAsync(user, ct);
    }

    // ✅ RefreshTokenAsync: validate/consume + BuildTokenResponseAsync
    public async Task<TokenResponse?> RefreshTokenAsync(string refreshToken, CancellationToken ct = default)
    {
        var user = await _refreshTokenService.ValidateAndConsumeAsync(refreshToken, ct);
        if (user is null)
            return null;

        return await BuildTokenResponseAsync(user, ct);
    }

    // ✅ BuildTokenResponseAsync: roles + access token + refresh token + expires
    private async Task<TokenResponse> BuildTokenResponseAsync(User user, CancellationToken ct)
    {
        var roles = await _userManager.GetRolesAsync(user);

        var accessToken = _jwtGenerator.GenerateAccessToken(user, roles);

        // Variant A (tövsiyə): RefreshTokenService özü JwtOptions-dan refresh müddətini götürür
        var refreshToken = await _refreshTokenService.CreateAsync(user, ct);

        // Variant B: əgər səndə CreateAsync(user, minutes, ct) varsa, bunu yaz:
        // var refreshToken = await _refreshTokenService.CreateAsync(user, _jwtOpt.RefreshExpirationMinutes, ct);

        return new TokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresAtUtc = DateTime.UtcNow.AddMinutes(_jwtOpt.ExpirationMinutes)
        };
    }
}