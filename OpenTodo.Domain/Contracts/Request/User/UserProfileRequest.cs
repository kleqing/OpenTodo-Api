using Microsoft.AspNetCore.Http;

namespace OpenTodo.Domain.Contracts.Request.User;

public class UserProfileRequest
{
    public string Email { get; set; } = string.Empty;
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string? UserName { get; set; }
    public DateTime DateOfBirth { get; set; }
    public string Address { get; set; } = string.Empty;
    public IFormFile? ProfilePictureUrl { get; set; }
}