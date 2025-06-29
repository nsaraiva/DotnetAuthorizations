using LearningJwt.Domain.Services;
using LearningJwt.Domain.Services.Interfaces;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddTransient<ITokenService, TokenService>();
builder.Services.AddTransient<IUserService, UserService>();

// Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(options =>
    {
        options.SaveToken = true;
        options.RequireHttpsMetadata = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidAudience = builder.Configuration["Jwt:ValidAudience"],
            ValidIssuer = builder.Configuration["Jwt:ValidIssuer"],
            ClockSkew = TimeSpan.Zero,
            // ** IMPORTANT: Configure to use JWKS endpoint **
            IssuerSigningKeyResolver = (token, securityToken, kidFromTokenHeader, parameters) => // <-- Renamed 'kid' to 'kidFromTokenHeader' for clarity
            {
                Console.WriteLine($"[JWKS Resolver] Token Header KID: {kidFromTokenHeader ?? "NULL or EMPTY"}"); // Log the KID from the token!

                var jwksUri = $"{parameters.ValidIssuer.TrimEnd('/')}/.well-known/jwks.json";
                Console.WriteLine($"[JWKS Resolver] Attempting to fetch JWKS from: {jwksUri}");

                try
                {
                    var discoveryClient = new HttpClient();
                    var jwksJson = discoveryClient.GetStringAsync(jwksUri).Result;
                    Console.WriteLine($"[JWKS Resolver] Successfully fetched JWKS content (partial):\n{jwksJson.Substring(0, Math.Min(jwksJson.Length, 500))}..."); // Log partial to avoid clutter

                    var jwks = new JsonWebKeySet(jwksJson);

                    if (jwks.Keys == null || !jwks.Keys.Any())
                    {
                        Console.WriteLine("[JWKS Resolver] JWKS 'keys' array is empty or null after parsing.");
                        return null; // No keys to provide
                    }

                    Console.WriteLine($"[JWKS Resolver] Found {jwks.Keys.Count} key(s) in JWKS.");
                    var matchedKeys = new List<SecurityKey>();

                    foreach (var key in jwks.Keys)
                    {
                        Console.WriteLine($"[JWKS Resolver] JWKS Key: Kid={key.Kid}, Kty={key.Kty}, Alg={key.Alg}");
                        if (key.Kid == kidFromTokenHeader)
                        {
                            Console.WriteLine($"[JWKS Resolver] Match found for KID: {key.Kid}");
                            matchedKeys.Add(key); // Add the JsonWebKey directly, it implicitly converts to SecurityKey
                        }
                    }

                    if (matchedKeys.Any())
                    {
                        Console.WriteLine($"[JWKS Resolver] Returning {matchedKeys.Count} matching key(s).");
                        return matchedKeys;
                    }
                    else
                    {
                        Console.WriteLine($"[JWKS Resolver] No matching key found in JWKS for token's KID: {kidFromTokenHeader ?? "NULL or EMPTY"}");
                        // Fallback: if KID is present in token but no match, return all keys.
                        // The library might still try to find one by other means,
                        // but it's generally best to return the specific key.
                        return jwks.Keys; // This returns JsonWebKey objects, which inherit from SecurityKey
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[JWKS Resolver] CRITICAL ERROR: {ex.Message}");
                    if (ex.InnerException != null)
                    {
                        Console.WriteLine($"[JWKS Resolver] Inner Exception: {ex.InnerException.Message}");
                    }
                    return null; // Must return null if keys cannot be resolved
                }
            }
        };

        // Add event handlers to log authentication failures
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                Console.WriteLine($"Authentication failed: {context.Exception.Message}");
                if (context.Exception.InnerException != null)
                {
                    Console.WriteLine($"Inner Exception: {context.Exception.InnerException.Message}");
                }
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                Console.WriteLine("Token successfully validated!");
                // Optionally log claims
                foreach (var claim in context.Principal.Claims)
                {
                    Console.WriteLine($"Claim: {claim.Type} = {claim.Value}");
                }
                return Task.CompletedTask;
            },
            OnChallenge = context =>
            {
                Console.WriteLine($"OnChallenge: {context.Error} - {context.ErrorDescription}");
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization(); // Enable authorization

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
