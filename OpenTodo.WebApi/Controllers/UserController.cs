using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenTodo.Application.Common;
using OpenTodo.Domain.Contracts.Request.User;
using OpenTodo.Domain.DTO;
using OpenTodo.Domain.Interfaces;

namespace OpenTodo.WebApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    private readonly IUserRepository _userRepository;

    public UserController(IUserRepository userRepository)
    {
        _userRepository = userRepository;
    }

    [Authorize]
    [HttpPost("get-current-user")]
    public async Task<IActionResult> GetCurrentUser()
    {
        var response = new BaseResultResponse<UserResponse>();

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized();
        }

        var result = await _userRepository.GetUserById(Guid.Parse(userId));
        if (result != null)
        {
            response.StatusCode = StatusCodes.Status200OK;
            response.Success = true;
            response.Message = "User found.";
            response.Data = new UserResponse
            {
                UserId = result.Id,
                FirstName = result.FirstName,
                LastName = result.LastName,
                UserName = result.UserName ?? string.Empty,
                Email = result.Email ?? string.Empty,
                PhoneNumber = result.PhoneNumber ?? string.Empty,
                Address = result.Address,
                DateOfBirth = result.DateOfBirth,
                ProfilePictureUrl = result.ProfilePictureUrl
            };
            return Ok(response);
        }
        else
        {
            response.StatusCode = StatusCodes.Status404NotFound;
            response.Success = false;
            response.Message = "User not found.";
            return NotFound(response);
        }
    }

    [HttpPost("update-profile")]
    [Authorize]
    public async Task<IActionResult> UpdateUserProfile(UserProfileRequest request)
    {
        var response = new BaseResultResponse<UserResponse>();

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized();
        }

        var result = await _userRepository.UpdateUserProfile(request);
        if (result != null)
        {
            response.StatusCode = StatusCodes.Status200OK;
            response.Success = true;
            response.Message = "User profile updated successfully.";
            response.Data = new UserResponse
            {
                UserId = result.Id,
                FirstName = result.FirstName,
                LastName = result.LastName,
                UserName = result.UserName ?? string.Empty,
                Email = result.Email ?? string.Empty,
                PhoneNumber = result.PhoneNumber ?? string.Empty,
                Address = result.Address,
                DateOfBirth = result.DateOfBirth,
                ProfilePictureUrl = result.ProfilePictureUrl
            };
            return Ok(response);
        }
        else
        {
            response.StatusCode = StatusCodes.Status404NotFound;
            response.Success = false;
            response.Message = "User not found.";
            return NotFound(response);
        }
    }

    [HttpPost("update-password")]
    [Authorize]
    public async Task<IActionResult> UpdateUserPassword([FromBody] UserPasswordRequest request)
    {
        var response = new BaseResultResponse<string>();
        
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        
        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized();
        }

        if (request.NewPassword != request.ConfirmPassword)
        {
            response.StatusCode = StatusCodes.Status203NonAuthoritative;
            response.Success = false;
            response.Message = "New password and confirm password do not match.";
            return BadRequest(response);
        }
        
        var result = await _userRepository.UpdateUserPassword(Guid.Parse(userId), request.OldPassword, request.NewPassword);
        if (result != null)
        {
            response.StatusCode = StatusCodes.Status200OK;
            response.Success = true;
            response.Message = "User password updated successfully.";
            return Ok(response);
        }
        else
        {
            response.StatusCode = StatusCodes.Status404NotFound;
            response.Success = false;
            response.Message = "User not found or password update failed.";
            return NotFound(response);
        }
    }
}