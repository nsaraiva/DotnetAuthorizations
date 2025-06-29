using Microsoft.AspNetCore.Mvc;

namespace LearningJwt.Api.Controllers;


[ApiController]
[Route(".well-known")]
public class JwksController : ControllerBase
{
    private readonly string _jwksFilePath;

    public JwksController()
    {
        _jwksFilePath = Path.Combine(Directory.GetCurrentDirectory(), "Keys", "jwks.json");
    }

    [HttpGet("jwks.json")]
    public async Task<IActionResult> GetJwksAsync()
    {
        if (!System.IO.File.Exists(_jwksFilePath))
        {
            return NotFound("JWKS file not found. Please ensure 'Keys/jwks.json' exists.");
        }
        var jwksContent = await System.IO.File.ReadAllTextAsync(_jwksFilePath);

        return Content(jwksContent, "application/json");
    }
}
