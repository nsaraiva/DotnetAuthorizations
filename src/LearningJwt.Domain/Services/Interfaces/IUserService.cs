using LearningJwt.Domain.Models;

namespace LearningJwt.Domain.Services.Interfaces;

public interface IUserService
{
    User? GetUser(string username, string password);
}
