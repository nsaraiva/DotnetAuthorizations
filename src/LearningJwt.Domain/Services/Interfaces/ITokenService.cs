using System.Security.Claims;

namespace LearningJwt.Domain.Services.Interfaces
{
    public interface ITokenService
    {
        string GenerateAccessToken(IEnumerable<Claim> claims);
    }
}