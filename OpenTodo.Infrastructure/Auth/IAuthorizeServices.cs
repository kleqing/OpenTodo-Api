using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using OpenTodo.Domain.Contracts.Request.Auth;
using OpenTodo.Domain.DTO;
using OpenTodo.Domain.Entities;

namespace OpenTodo.Infrastructure.Auth;

public interface IAuthorizeServices
{
    Task<Users> LoginWithGoogle(ClaimsPrincipal claimsPrincipal);
    Task<Users> CreateAccount(RegisterRequest request);
    Task<UserResponse?> Login(LoginRequest request);
    Task InitiatePasswordReset(string email);
    Task<bool> VerifyPasswordResetToken(string token);
    Task<IdentityResult> ResetPassword(ResetPasswordRequest request);
    Task ResendEmailConfirmation(Users user);
    Task Logout(Users user);
    
}