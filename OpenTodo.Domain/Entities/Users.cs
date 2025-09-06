using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace OpenTodo.Domain.Entities;

public class Users : IdentityUser<Guid>
{
    [Required] [MaxLength(20)] public string FirstName { get; set; } = string.Empty;
    [Required] [MaxLength(20)] public string LastName { get; set; } = string.Empty;
    [Required] [MaxLength(20)] public override string? UserName { get; set; }
    public DateTime DateOfBirth { get; set; }
    [MaxLength(100)] public string Address { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.Now;
    [MaxLength(50)] public string ProfilePictureUrl { get; set; } = string.Empty;
    [MaxLength(100)] public string? RefreshToken { get; set; }
    public DateTime? RefreshTokenExpiryTime { get; set; }
    
    public virtual ICollection<Todos> Todos { get; set; } = new List<Todos>();
}