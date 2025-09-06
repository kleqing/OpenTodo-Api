using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenTodo.Domain.Entities;
using OpenTodo.Domain.Jwt;
using OpenTodo.Infrastructure.Auth;

namespace OpenTodo.Application.Services.Auth;

public class AuthTokenProcess : IAuthTokenProcess
{
    private readonly Jwt _jwt;
    private readonly IHttpContextAccessor _contextAccessor;

    public AuthTokenProcess(IOptions<Jwt> jwt, IHttpContextAccessor contextAccessor)
    {
        _jwt = jwt.Value;
        _contextAccessor = contextAccessor;
    }

    public (string Token, DateTime Expiry) GenerateToken(Users user)
    {
        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Secret));
        var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()) //* Set the NameIdentifier claim to the user's ID
        };

        var expires = DateTime.UtcNow.AddMinutes(_jwt.ExpiryInMinutes);

        var token = new JwtSecurityToken(issuer: _jwt.Issuer,
            audience: _jwt.Audience,
            claims: claims,
            expires: expires,
            signingCredentials: credentials);

        var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

        return (jwtToken, expires);
    }

    public string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    public void WriteAuthTokenAsHttpOnlyCookie(string cookieName, string token, DateTime expiry)
    {
        _contextAccessor.HttpContext?.Response.Cookies.Append(cookieName, token, BuildCookieOptions(expiry));
    }

    public void DeleteAuthTokenCookie(string key)
    {
        var context = _contextAccessor.HttpContext;
        context?.Response.Cookies.Delete(key, BuildCookieOptions());
    }

    private CookieOptions BuildCookieOptions(DateTime? expiry = null)
    {
        return new CookieOptions
        {
            Expires = expiry,
            HttpOnly = true,
            IsEssential = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            //* Path = "/" // Uncomment this line if you want the cookie to be accessible across all paths
        };
    }
}