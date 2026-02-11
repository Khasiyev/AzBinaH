using Domain.Entities;

namespace Application.Abstracts.Services;

public interface IJwtTokenGenerator
{
    string GenerateToken(User user);
}
