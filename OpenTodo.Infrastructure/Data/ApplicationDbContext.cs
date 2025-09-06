using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OpenTodo.Domain.Entities;

namespace OpenTodo.Infrastructure.Data;

public class ApplicationDbContext : IdentityDbContext<Users, IdentityRole<Guid>, Guid>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }
    
    public DbSet<Todos> Todos { get; set; } 
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        
        modelBuilder.Entity<Todos>()
            .HasKey(t => t.TodoId);

        modelBuilder.Entity<Todos>()
            .HasOne(u => u.User)
            .WithMany(t => t.Todos)
            .HasForeignKey(u => u.UserId);
    }
}