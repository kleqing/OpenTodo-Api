using Microsoft.AspNetCore.Identity;
using OpenTodo.Domain.Enum;

namespace OpenTodo.Application.Services.Role;

public class RoleServices
{
    public static async Task SeedRole(RoleManager<IdentityRole<Guid>> roleManager)
    {
        var roleValues = Enum.GetValues<EntityEnum.Role>();
        
        foreach (var roleValue in roleValues)
        {
            var roleName = roleValue.ToString().ToUpper();
            
            var roleExists = await roleManager.RoleExistsAsync(roleName);
            if (!roleExists)
            {
                await roleManager.CreateAsync(new IdentityRole<Guid>(roleName));
            }
        }
    }
}