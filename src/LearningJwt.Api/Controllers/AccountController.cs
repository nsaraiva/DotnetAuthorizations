using LearningJwt.Domain.Models;
using LearningJwt.Domain.Services.Interfaces;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace LearningJwt.Api.Controllers;

[ApiController]
[Route("/accounts")]
public class AccountController : ControllerBase
{
    private readonly IUserService _userService;
    private readonly ITokenService _tokenService;

    public AccountController(ITokenService tokenService, IUserService userService)
    {
        _tokenService = tokenService;
        _userService = userService;
    }

    [HttpPost("login")]
    public IActionResult Login(Login login)
    {
        try
        {
            var user = _userService.GetUser(login.Username, login.Password);

            if (user == null)
            {
                return Unauthorized("Invalid username or password");
            }

            var claims = new List<Claim>
            {
                new (ClaimTypes.Name, user.UserName),
                new (JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())

            };

            foreach (var role in user.Roles)
            {
                claims.Add(new(ClaimTypes.Role, role));
            }

            return Ok(_tokenService.GenerateAccessToken(claims));
        }
        catch (Exception)
        {
            return Unauthorized();
        }
    }
}