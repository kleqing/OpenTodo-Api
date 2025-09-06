using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using OpenTodo.Domain.Contracts.Request.Auth;
using OpenTodo.Domain.DTO;
using OpenTodo.Domain.Entities;
using OpenTodo.Domain.Enum;
using OpenTodo.Infrastructure.Auth;
using OpenTodo.Shared.Exceptions;
using StackExchange.Redis;

namespace OpenTodo.Application.Services.Auth;

public class AuthorizeServices : IAuthorizeServices
{
    private readonly UserManager<Users> _userManager;
    private readonly IAuthTokenProcess _authTokenProcess;
    private readonly IEmailSender _emailSender;
    private readonly IDatabase _redis;
    private readonly TimeSpan _tokenExpiryTime;

    private const string RedisPasswordResetPrefix = "reset-password:";


    public AuthorizeServices(UserManager<Users> userManager, IAuthTokenProcess authTokenProcess,
        IEmailSender emailSender, IDatabase redis)
    {
        _userManager = userManager;
        _authTokenProcess = authTokenProcess;
        _emailSender = emailSender;
        _redis = redis;
        _tokenExpiryTime =
            TimeSpan.FromMinutes(int.Parse(Environment.GetEnvironmentVariable("JWT_EXPIRY_MINUTES") ?? "15"));
    }

    public async Task<Users> LoginWithGoogle(ClaimsPrincipal claimsPrincipal)
    {
        if (claimsPrincipal == null)
        {
            throw new GlobalException("ClaimsPrincipal is null");
        }

        var email = claimsPrincipal.FindFirstValue(ClaimTypes.Email);

        if (email == null)
        {
            throw new GlobalException("Register", "Email not found");
        }

        var user = await _userManager.FindByEmailAsync(email);

        if (user == null)
        {
            var newUser = new Users
            {
                Email = email,
                UserName = email.Split('@')[0],
                FirstName = claimsPrincipal.FindFirstValue(ClaimTypes.GivenName) ?? string.Empty,
                LastName = claimsPrincipal.FindFirstValue(ClaimTypes.Surname) ?? string.Empty,
                EmailConfirmed = true,
                ProfilePictureUrl = claimsPrincipal.FindFirstValue("picture") ?? string.Empty
            };

            var result = await _userManager.CreateAsync(newUser);

            if (!result.Succeeded)
            {
                throw new GlobalException("Register",
                    $"Unable to create user: {string.Join(", ", result.Errors.Select(e => e.Description))}");
            }

            await _userManager.AddToRoleAsync(newUser, EntityEnum.Role.User.ToString());
        }

        var (jwtToken, expiry) = _authTokenProcess.GenerateToken(user!);
        var refreshToken = _authTokenProcess.GenerateRefreshToken();
        var refreshTokenExpiry = DateTime.UtcNow.AddDays(7);

        user!.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = refreshTokenExpiry;
        await _userManager.UpdateAsync(user);

        _authTokenProcess.WriteAuthTokenAsHttpOnlyCookie("ACCESS_TOKEN", jwtToken, expiry);
        _authTokenProcess.WriteAuthTokenAsHttpOnlyCookie("REFRESH_TOKEN", refreshToken, refreshTokenExpiry);

        return user;
    }

    public async Task<Users> CreateAccount(RegisterRequest request)
    {
        try
        {
            var isUserExists = await _userManager.FindByEmailAsync(request.Email);

            if (isUserExists != null)
            {
                throw new GlobalException("Register", "Email already exists");
            }

            var checkUserName = await _userManager.FindByNameAsync(request.UserName);
            if (checkUserName != null)
            {
                throw new GlobalException("Register", "Username already exists");
            }

            var user = new Users
            {
                Id = new Guid(),
                FirstName = request.FirstName,
                LastName = request.LastName,
                UserName = request.UserName,
                Email = request.Email,
                PhoneNumber = request.PhoneNumber,
                Address = request.Address,
                DateOfBirth = request.DateOfBirth,
                ProfilePictureUrl = request.ProfilePictureUrl ?? string.Empty,
                CreatedAt = request.CreatedAt
            };

            var result = await _userManager.CreateAsync(user, request.Password);

            if (!result.Succeeded)
            {
                throw new GlobalException("Register",
                    $"Unable to create user: {string.Join(", ", result.Errors.Select(e => e.Description))}");
            }

            await _userManager.AddToRoleAsync(user, EntityEnum.Role.User.ToString());

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var encodedToken = WebUtility.UrlEncode(token);

            var confirmationLink =
                $"{Environment.GetEnvironmentVariable("BACKEND_URL")}/api/Auth/confirm-email?userId={user.Id}&token={encodedToken}";

            await _emailSender.SendEmailAsync(user.Email, "Verify your email", confirmationLink);

            return user;
        }
        catch (Exception ex)
        {
            throw new GlobalException("Register", ex.Message);
        }
    }

    public async Task<UserResponse?> Login(LoginRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);

        if (user == null)
        {
            throw new GlobalException("Login", "Account not found");
        }

        var isPasswordValid = await _userManager.CheckPasswordAsync(user, request.Password);

        if (!isPasswordValid)
        {
            throw new GlobalException("Login", "Invalid password");
        }

        var (jwtToken, expiry) = _authTokenProcess.GenerateToken(user);
        var refreshToken = _authTokenProcess.GenerateRefreshToken();
        var refreshTokenExpiry = DateTime.UtcNow.AddDays(7);

        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = refreshTokenExpiry;
        await _userManager.UpdateAsync(user);

        _authTokenProcess.WriteAuthTokenAsHttpOnlyCookie("ACCESS_TOKEN", jwtToken, expiry);
        _authTokenProcess.WriteAuthTokenAsHttpOnlyCookie("REFRESH_TOKEN", refreshToken, refreshTokenExpiry);

        return new UserResponse
        {
            UserId = user.Id,
            FirstName = user.FirstName,
            LastName = user.LastName,
            UserName = user.UserName ?? string.Empty,
            Email = user.Email ?? string.Empty,
            PhoneNumber = user.PhoneNumber ?? string.Empty,
            Address = user.Address,
            DateOfBirth = user.DateOfBirth,
            ProfilePictureUrl = user.ProfilePictureUrl
        };
    }

    public async Task InitiatePasswordReset(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);

        if (user != null && await _userManager.IsEmailConfirmedAsync(user))
        {
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var redisKey = $"{RedisPasswordResetPrefix}{token}";

            try
            {
                bool result =
                    await _redis.StringSetAsync(redisKey, user.Id.ToString(), _tokenExpiryTime, When.NotExists);

                if (result)
                {
                    var encodedToken = WebUtility.UrlEncode(token);
                    var resetLink =
                        $"{Environment.GetEnvironmentVariable("BACKEND_URL")}/api/Auth/reset-password?token={encodedToken}";

                    await _emailSender.SendEmailAsync(user.Email ?? string.Empty, "Reset your password", resetLink);
                }
                else
                {
                    throw new GlobalException("Reset Password",
                        "Password reset request already exists. Please try again later.");
                }
            }
            catch (Exception ex)
            {
                throw new GlobalException("Reset Password", $"Error saving token to Redis: {ex.Message}");
            }
        }
        else
        {
            throw new GlobalException("Reset Password", "Email not found or not confirmed");
        }
    }
    
    public async Task<bool> VerifyPasswordResetToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return false;
        }
        
        var redisKey = $"{RedisPasswordResetPrefix}{token}";
        try
        {
            return await _redis.KeyExistsAsync(redisKey);
        }
        catch (Exception ex)
        {
            throw new GlobalException("Verify Password Reset Token",
                $"Error checking token in Redis: {ex.Message}");
        }
    }
    
    public async Task<IdentityResult> ResetPassword(ResetPasswordRequest request)
    {
        var redisKey = $"{RedisPasswordResetPrefix}{request.Token}";
        RedisValue userIdValue;

        try
        {
            userIdValue = await _redis.StringGetAsync(redisKey);
        }
        catch (Exception ex)
        {
            throw new GlobalException("Reset Password", $"Error retrieving token from Redis: {ex.Message}", ex);
        }

        if (!userIdValue.HasValue)
        {
            throw new GlobalException("Reset Password", "Invalid or expired password reset token");
        }

        var userId = userIdValue.ToString();
        var user = await _userManager.FindByIdAsync(userId);

        if (user == null)
        {
            throw new GlobalException("Reset Password", "User not found");
        }

        IdentityResult result = await _userManager.ResetPasswordAsync(user, request.Token!, request.NewPassword);

        if (result.Succeeded)
        {
            try
            {
                //* Remove the token from Redis after successful password reset
                await _redis.KeyDeleteAsync(redisKey);
            }
            catch (Exception ex)
            {
                throw new GlobalException("Reset Password",
                    $"Error deleting token from Redis: {ex.Message}", ex);
            }
        }
        else
        {
            throw new GlobalException("Reset Password",
                $"Unable to reset password: {string.Join(", ", result.Errors.Select(e => e.Description))}");
        }

        return result;
    }

    public async Task ResendEmailConfirmation(Users user)
    {
        if (!await _userManager.IsEmailConfirmedAsync(user))
        {
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var encodedToken = WebUtility.UrlEncode(token);

            string confirmationLink =
                $"{Environment.GetEnvironmentVariable("BACKEND_URL")}/api/Auth/confirm-email?userId={user.Id}&token={encodedToken}";
            await _emailSender.SendEmailAsync(user.Email!, "Verify your email", confirmationLink);
        }
        else
        {
            throw new GlobalException("Resend Email Confirmation",
                "Email is already confirmed. No need to resend confirmation email.");
        }
    }

    public async Task Logout(Users user)
    {
        user.RefreshToken = null;
        user.RefreshTokenExpiryTime = null;
        await _userManager.UpdateAsync(user);

        _authTokenProcess.DeleteAuthTokenCookie("ACCESS_TOKEN");
        _authTokenProcess.DeleteAuthTokenCookie("REFRESH_TOKEN");
    }
}