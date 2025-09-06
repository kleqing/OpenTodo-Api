using System.ComponentModel.DataAnnotations;

namespace OpenTodo.Domain.Contracts.Request.Auth;

public class ResetPasswordRequest
{
    public string? Token { get; set; }
    [Required]
    public string NewPassword { get; set; } = string.Empty;
    [Required]
    public string ConfirmPassword { get; set; } = string.Empty;
}