using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenTodo.Domain.Entities;
using OpenTodo.Infrastructure.Data;
using OpenTodo.Shared.Exceptions;

namespace OpenTodo.Infrastructure.Repositories;

public class TodoRepository
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<Users> _userManager;
    
    public TodoRepository(ApplicationDbContext context, UserManager<Users> userManager)
    {
        _context = context;
        _userManager = userManager;
    }

    public async Task<List<Todos>> GetTodoListFromUserId(Guid userId)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString());

        if (user == null)
        {
            throw new GlobalException("User not found");
        }
        
        var todoList = await _context.Todos.Where(x => x.UserId == user.Id).ToListAsync();

        if (todoList == null)
        {
            throw new GlobalException("No todo found on this user");
        }   

        return todoList;
    }

    public async Task<Todos?> UpdateTodo(Todos todos)
    {
        
    }
}