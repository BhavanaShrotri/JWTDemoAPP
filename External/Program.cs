using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

var jwkString = "{\"additionalData\":{},\"alg\":null,\"crv\":null,\"d\":null,\"dp\":null,\"dq\":null,\"e\":\"AQAB\",\"k\":null,\"keyId\":null,\"keyOps\":[],\"kid\":null,\"kty\":\"RSA\",\"n\":\"xUt-FeBiWr7VxWami2yagQC9yKJ2CrCeRJdoU6g2f_UYn_u1-WihfXc-tthx2C2NZX-39Ddd0AdDnBvjDYCV5ZXtO1qrJO2fcGchV-CGU8QDtQz4MPMIeVKbs2YLgkCeeYp1z93XK1Q-tVgIjlq57MVOfXpSgW5tvtQLOqX1zIY-c8kHd_-9ARhr1wS4W9JBcFX9IesX-kWz1R31WHGeF2Q0Jt8vyOGGxPhx2CrvdD2O6Jo8s01Aox6croqoNg_ge-ob6ZPcUvXDcKy0cosLIugpeSYQGZlsfe39JOxt_5rlvddYECX-dztgFGbjmY1h34Kp9jmHR_Nj7HfmEHM0UQ\",\"oth\":null,\"p\":null,\"q\":null,\"qi\":null,\"use\":null,\"x\":null,\"x5c\":[],\"x5t\":null,\"x5tS256\":null,\"x5u\":null,\"y\":null,\"keySize\":2048,\"hasPrivateKey\":false,\"cryptoProviderFactory\":{\"cryptoProviderCache\":{},\"customCryptoProvider\":null,\"cacheSignatureProviders\":true,\"signatureProviderObjectPoolCacheSize\":64}}";

builder.Services.AddAuthentication("jwt")
    .AddJwtBearer("jwt", o =>
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
            JsonWebKey.Create(jwkString)
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
    var token = handler.CreateToken(new SecurityTokenDescriptor()
    {
        Issuer = "https://localhost:7178",
        Subject = new ClaimsIdentity(new[]
        {
            new Claim("sub", Guid.NewGuid().ToString()),
            new Claim("name","Bhavana")
        }),
        SigningCredentials = new SigningCredentials(JsonWebKey.Create(jwkString), SecurityAlgorithms.RsaSha256)
    });

    return token;
});

app.Run();
