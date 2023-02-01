using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

var jwkString = "{\"additionalData\":{},\"alg\":null,\"crv\":null,\"d\":null,\"dp\":null,\"dq\":null,\"e\":\"AQAB\",\"k\":null,\"keyId\":null,\"keyOps\":[],\"kid\":null,\"kty\":\"RSA\",\"n\":\"6UViZRYoWJ7Z4wLISZ-d4bMrNdmqWYq4Z0EVBPh4dqvsj7n02T8F-sfhdHBO6RxqtPejcGkcov-UWk0esncON0akoavdGtazz7lfHmmbg826BD72WpzyTfQP-osR8GF0_9ZWDFJLKIvWRWlnI-8nCpAL9jXeYkiiaNdFsi9-xMHEE8QKFBuUaM91hjvcAt60CGm3c02Gnn-LIJ1AiwWL9sZOpjOzitsiMZuCPH66RsCMMp7Q65JuEhlhc-AY7UPWJtEd_83LyScsdryVKdQD8xonqvonbDURQ8uS48k5Yk--raYboW5Gxtzb9RxAMr0_nSo7Ei9FjcFyaXB1ntgncQ\",\"oth\":null,\"p\":null,\"q\":null,\"qi\":null,\"use\":null,\"x\":null,\"x5c\":[],\"x5t\":null,\"x5tS256\":null,\"x5u\":null,\"y\":null,\"keySize\":2048,\"hasPrivateKey\":false,\"cryptoProviderFactory\":{\"cryptoProviderCache\":{},\"customCryptoProvider\":null,\"cacheSignatureProviders\":true,\"signatureProviderObjectPoolCacheSize\":64}}";

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
