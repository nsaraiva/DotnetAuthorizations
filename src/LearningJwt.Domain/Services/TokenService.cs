using LearningJwt.Domain.Services.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace LearningJwt.Domain.Services
{
    public class TokenService : ITokenService
    {
        private readonly IConfiguration _configuration;

        public TokenService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string GenerateAccessToken(IEnumerable<Claim> claims)
        {
            // Load the private RSA key from file
            var privateJwkFilePath = Path.Combine(Directory.GetCurrentDirectory(), "Keys", "rsa_private_key.json");
            var privateJwkJson = System.IO.File.ReadAllText(privateJwkFilePath);
            var privateJwk = JsonWebKey.Create(privateJwkJson);


            // Ensure the key is an RSA key and has the private components
            if (!privateJwk.Kty.Equals("RSA", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("The loaded key is not an RSA key.");
            }
            if (!privateJwk.HasPrivateKey)
            {
                throw new InvalidOperationException("The loaded RSA JWK does not contain private key components.");
            }

            RSA rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters
            {
                Modulus = Base64UrlEncoder.DecodeBytes(privateJwk.N),
                Exponent = Base64UrlEncoder.DecodeBytes(privateJwk.E),
                D = Base64UrlEncoder.DecodeBytes(privateJwk.D),
                P = Base64UrlEncoder.DecodeBytes(privateJwk.P),
                Q = Base64UrlEncoder.DecodeBytes(privateJwk.Q),
                DP = Base64UrlEncoder.DecodeBytes(privateJwk.DP),
                DQ = Base64UrlEncoder.DecodeBytes(privateJwk.DQ),
                InverseQ = Base64UrlEncoder.DecodeBytes(privateJwk.QI)
            });

            var rsaSecurityKey = new RsaSecurityKey(rsa);
            rsaSecurityKey.KeyId = privateJwk.Kid; // Set the KeyId from the JWK

            var credentials = new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256); // Use RS256


            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:ValidIssuer"],
                audience: _configuration["Jwt:ValidAudience"],
                claims: claims,
                notBefore: DateTime.Now,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
