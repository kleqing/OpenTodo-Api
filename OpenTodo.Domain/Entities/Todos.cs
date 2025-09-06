using System.ComponentModel.DataAnnotations;

namespace OpenTodo.Domain.Entities;

public class Todos
{
    public Guid TodoId { get; set; }
    public Guid UserId { get; set; }
    [MaxLength(1000)] public string Title { get; set; } = string.Empty;
    [MaxLength(1000)] public string? Description { get; set; }
    public bool IsCompleted { get; set; }
    public DateTime? DueDate { get; set; }
    public DateTime CreatedDate { get; set; } = DateTime.Now;
    public DateTime UpdatedAt { get; set; } = DateTime.Now;

    public virtual Users User { get; set; } = new Users();
}