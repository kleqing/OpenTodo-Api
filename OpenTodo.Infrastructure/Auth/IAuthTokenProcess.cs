using OpenTodo.Domain.Entities;

namespace OpenTodo.Infrastructure.Auth;

public interface IAuthTokenProcess
{
    (string Token, DateTime Expiry) GenerateToken(Users user);
    string GenerateRefreshToken();
    void WriteAuthTokenAsHttpOnlyCookie(string cookieName, string token, DateTime expiry);
    void DeleteAuthTokenCookie(string key);
}