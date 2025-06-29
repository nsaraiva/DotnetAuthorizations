using LearningJwt.Domain.Models;
using LearningJwt.Domain.Services.Interfaces;

namespace LearningJwt.Domain.Services;

public class UserService : IUserService
{
    private readonly List<User> _users =
    [
        new()
        {
            UserName = "admin",
            Password = "admin123",
            Roles = ["Addmin"]
        },
        new()
        {
            UserName = "user",
            Password = "user123",
            Roles = ["User"]
        }
    ];

    public User? GetUser(string username, string password)
    {
        return _users.FirstOrDefault(u => u.UserName == username && u.Password == password);
    }
}
