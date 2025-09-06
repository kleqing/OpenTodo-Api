using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenTodo.Application.Common;
using OpenTodo.Domain.Contracts.Request.Auth;
using OpenTodo.Domain.DTO;
using OpenTodo.Domain.Entities;
using OpenTodo.Infrastructure.Auth;
using OpenTodo.Shared.Constant;

namespace OpenTodo.WebApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthorizeServices _authorizeService;
    private readonly UserManager<Users> _userManager;

    public AuthController(IAuthorizeServices authorizeService, UserManager<Users> userManager)
    {
        _authorizeService = authorizeService;
        _userManager = userManager;
    }
    
    [AllowAnonymous]
    [HttpGet("login/google")]
    public IActionResult LoginWithGoogle(string returnUrl)
    {
        var redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Auth", new { returnUrl });
        var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
        return Challenge(properties, GoogleDefaults.AuthenticationScheme);
    }
    
    [HttpGet("external-login-callback")]
    public async Task<IActionResult> ExternalLoginCallback(string returnUrl)
    {
        var result = await HttpContext.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);

        if (!result.Succeeded)
        {
            return BadRequest("Failed to authenticate with Google.");
        }

        var claimsPrincipal = result.Principal;
        await _authorizeService.LoginWithGoogle(claimsPrincipal);

        var email = claimsPrincipal.FindFirst(ClaimTypes.Email)?.Value ?? string.Empty;
        var name = claimsPrincipal.FindFirst(ClaimTypes.GivenName)?.Value + " " +
                   claimsPrincipal.FindFirst(ClaimTypes.Surname)?.Value;
        var avatar = claimsPrincipal.FindFirst("picture")?.Value ?? string.Empty;

        var frontendUrl =
            $"{returnUrl}?email={Uri.EscapeDataString(email)}&name={Uri.EscapeDataString(name)}&avatar={Uri.EscapeDataString(avatar)}";
        return Redirect(frontendUrl);
    }

    [AllowAnonymous]
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        var response = new BaseResultResponse<Users>();

        try
        {
            var user = await _authorizeService.CreateAccount(request);

            response.StatusCode = StatusCodes.Status201Created;
            response.Success = true;
            response.Message = LoginConstant.AccountCreated;
            response.Data = user;
            return Ok(response);
        }
        catch (Exception ex)
        {
            response.StatusCode = StatusCodes.Status500InternalServerError;
            response.Success = false;
            response.Message = ex.Message;
            response.Errors = new List<string> { ex.Message };
            response.Data = null;
            return BadRequest(response);
        }
        
    }

    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var response = new BaseResultResponse<UserResponse>();

        try
        {
            var user = await _authorizeService.Login(request);
            
            response.StatusCode = StatusCodes.Status200OK;
            response.Success = true;
            response.Message = LoginConstant.LoginSuccess;
            response.Data = user;
            return Ok(response);
        }
        catch (Exception ex)
        {
            response.StatusCode = StatusCodes.Status500InternalServerError;
            response.Success = false;
            response.Message = "Login failed.";
            response.Errors = new List<string> { ex.Message };
            response.Data = null;
            return BadRequest(response);
        }
    }

    [AllowAnonymous]
    [HttpGet("confirm-email")]
    public async Task<IActionResult> ConfirmEmail(string userId, string token)
    {
        var user = await _userManager.FindByIdAsync(userId);
        
        if (user == null)
        {
            return BadRequest("User not found.");
        }
        
        var result = await _userManager.ConfirmEmailAsync(user, token);
        
        if (result.Succeeded)
        {
            return Redirect(
                $"{Environment.GetEnvironmentVariable("FRONTEND_URL")}/verify-success?verifiedEmail={Uri.EscapeDataString(user.Email ?? string.Empty)}");
        }
        
        return BadRequest("Email confirmation failed.");
    }
    
    [AllowAnonymous]
    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword(string email)
    {
        var response = new BaseResultResponse<string>();

        try
        {
            await _authorizeService.InitiatePasswordReset(email);
            response.StatusCode = StatusCodes.Status200OK;
            response.Success = true;
            response.Message = LoginConstant.SendEmailSuccess;
            response.Data = "Password reset email sent successfully.";
            return Ok(response);
        }
        catch (Exception ex)
        {
            response.StatusCode = StatusCodes.Status500InternalServerError;
            response.Success = false;
            response.Message = ex.Message;
            response.Errors = new List<string> { ex.Message };
            response.Data = null;
            return BadRequest(response);
        }
    }
    
    [HttpGet("reset-password/verify")]
    public async Task<IActionResult> VerifyResetToken([FromQuery] string token)
    {
        var reponse = new BaseResultResponse<bool>();

        if (string.IsNullOrEmpty(token))
        {
            reponse.StatusCode = StatusCodes.Status400BadRequest;
            reponse.Success = false;
            reponse.Message = "Token is required.";
            return BadRequest(reponse);
        }
        
        var isTokenValid = await _authorizeService.VerifyPasswordResetToken(token);
        if (!isTokenValid)
        {
            reponse.StatusCode = StatusCodes.Status400BadRequest;
            reponse.Success = false;
            reponse.Message = "Invalid or expired token.";
            return BadRequest(reponse);
        }
        
        reponse.StatusCode = StatusCodes.Status200OK;
        reponse.Success = true;
        reponse.Message = "Token is valid.";
        return Ok(reponse);
    }

    [HttpPost("reset-password")]
    [AllowAnonymous]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        var response = new BaseResultResponse<string>();

        if (string.IsNullOrEmpty(request.Token))
        {
            return BadRequest("Token is required.");
        }

        if (request.NewPassword != request.ConfirmPassword)
        {
            return BadRequest("Passwords do not match.");
        }

        try
        {
            IdentityResult result = await _authorizeService.ResetPassword(request);
            
            if (result.Succeeded)
            {
                response.StatusCode = StatusCodes.Status200OK;
                response.Success = true;
                response.Message = "Password reset successfully.";
                return Ok(response);
            }
            else
            {
                response.StatusCode = StatusCodes.Status400BadRequest;
                response.Success = false;
                response.Message = "Password reset failed.";
                response.Errors = result.Errors.Select(e => e.Description).ToList();
                return BadRequest(response);
            }
        }
        catch (Exception ex)
        {
            response.StatusCode = StatusCodes.Status500InternalServerError;
            response.Success = false;
            response.Message = ex.Message;
            response.Errors = new List<string> { ex.Message };
            return BadRequest(response);
        }
    }

    [HttpPost("resend-email-confirmation")]
    public async Task<IActionResult> ResendEmailConfirmation(string email)
    {
        var response = new BaseResultResponse<Users>();

        try
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                response.StatusCode =  StatusCodes.Status404NotFound;
                response.Success = false;
                response.Message = LoginConstant.AccountNotFound;
                return BadRequest(response);
            }
            
            await _authorizeService.ResendEmailConfirmation(user);
            response.StatusCode = StatusCodes.Status200OK;
            response.Success = true;
            response.Message = LoginConstant.SendEmailSuccess;
            response.Data = user;
            return Ok(response);
        }
        catch (Exception ex)
        {
            response.StatusCode = StatusCodes.Status500InternalServerError;
            response.Success = false;
            response.Message = ex.Message;
            response.Errors = new List<string> { ex.Message };
            response.Data = null;
            return BadRequest(response);
        }
    }

    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        var response = new BaseResultResponse<string>();

        try
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrEmpty(userId))
            {
                response.StatusCode = 400;
                response.Success = false;
                response.Message = "User not found.";
                return BadRequest(response);
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                response.StatusCode = 404;
                response.Success = false;
                response.Message = LoginConstant.AccountNotFound;
                return BadRequest(response);
            }

            // Sign out the user
            await _authorizeService.Logout(user);

            response.StatusCode = 200;
            response.Success = true;
            response.Message = LoginConstant.LogoutSuccess;
            return Ok(response);
        }
        catch (Exception ex)
        {
            response.StatusCode = 500;
            response.Success = false;
            response.Message = ex.Message;
            response.Errors = new List<string> { ex.Message };
            response.Data = null;
            return BadRequest(response);
        }
    }
}