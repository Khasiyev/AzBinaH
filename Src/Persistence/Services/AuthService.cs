using Application.Abstracts.Services;
using Application.Dtos.AuthDtos;
using Domain.Entities;
using Microsoft.AspNetCore.Identity;

namespace Persistence.Services;

public class AuthService : IAuthService
{
    private readonly UserManager<User> _userManager;
    private readonly SignInManager<User> _signInManager;
    private readonly IJwtTokenGenerator _jwtGenerator;

    public AuthService(
        UserManager<User> userManager,
        SignInManager<User> signInManager,
        IJwtTokenGenerator jwtGenerator)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _jwtGenerator = jwtGenerator;
    }

    public async Task<(bool Success, string? Error)> RegisterAsync(RegisterRequest request, CancellationToken ct = default)
    {
        var user = new User
        {
            UserName = request.UserName,
            Email = request.Email,
            FullName = request.FullName
        };

        var result = await _userManager.CreateAsync(user, request.Password);

        if (!result.Succeeded)
        {
            var error = string.Join("; ", result.Errors.Select(e => e.Description));
            return (false, error);
        }

        return (true, null);
    }

    public async Task<string?> LoginAsync(LoginRequest request, CancellationToken ct = default)
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

        return _jwtGenerator.GenerateToken(user);
    }
}
