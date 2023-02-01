using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

var rsaKey = RSA.Create();
rsaKey.ImportRSAPrivateKey(File.ReadAllBytes("key"), out _);

builder.Services.AddAuthentication("jwt").AddJwtBearer("jwt", o =>
{
    o.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateAudience = false,
        ValidateIssuer = false,
    };

    o.Events = new Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerEvents()
    {
        OnMessageReceived = (ctx) =>
        {
            if (ctx.Request.Query.ContainsKey("t"))
            {
                ctx.Token = ctx.Request.Query["t"];
            }
            return Task.CompletedTask;
        }
    };

    o.Configuration = new Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration()
    {
        SigningKeys =
        {
            new RsaSecurityKey(rsaKey) 
        }
    };

    o.MapInboundClaims = false;

});

var app = builder.Build();

app.UseAuthentication();

app.MapGet("/", (HttpContext ctx) => ctx.User.FindFirst("name")?.Value ?? "empty");

app.MapGet("/jwt", () =>
{
    var handler = new JsonWebTokenHandler();
    var key = new RsaSecurityKey(rsaKey);
    var token = handler.CreateToken(new SecurityTokenDescriptor()
    {
        Issuer = "https://localhost:7178",
        Subject = new ClaimsIdentity(new[]
        {
            new Claim("sub", Guid.NewGuid().ToString()),
            new Claim("name","Bhavana")
        }),
        SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
    });

    return token;

});

app.MapGet("/jwk-public", () =>
{
    var publicKey = RSA.Create();
    publicKey.ImportRSAPublicKey(publicKey.ExportRSAPublicKey(), out _);
    var key = new RsaSecurityKey(publicKey);
    return JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
});

app.MapGet("/jwk-private", () =>
{
    var key = new RsaSecurityKey(rsaKey);
    return JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
});

app.Run();
