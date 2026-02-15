using Domain.Entities;

namespace Application.Abstracts.Services;

public interface IJwtTokenGenerator
{
    string GenerateAccessToken(User user, IEnumerable<string> roles);
}
