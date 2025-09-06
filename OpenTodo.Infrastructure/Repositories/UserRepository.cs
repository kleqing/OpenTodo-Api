using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenTodo.Domain.Contracts.Request.User;
using OpenTodo.Domain.Entities;
using OpenTodo.Domain.Interfaces;
using OpenTodo.Infrastructure.Data;
using OpenTodo.Shared.Exceptions;
using OpenTodo.Shared.Utils;

namespace OpenTodo.Infrastructure.Repositories;

public class UserRepository : IUserRepository
{
    private readonly ApplicationDbContext _context;
    private readonly CloudinaryUploader _cloudinaryUploader;
    private readonly UserManager<Users> _userManager;
    
    public UserRepository(ApplicationDbContext context, CloudinaryUploader cloudinaryUploader, UserManager<Users> userManager)
    {
        _context = context;
        _cloudinaryUploader = cloudinaryUploader;
        _userManager = userManager;
    }
    
    public async Task<Users?> GetUserById(Guid userId)
    {
        return await _context.Users.FirstOrDefaultAsync(x => x.Id == userId);
    }

    public async Task<Users?> UpdateUserProfile(UserProfileRequest request)
    {
        var isUserExists = await _userManager.FindByEmailAsync(request.Email);

        if (isUserExists != null)
        {
            try
            {
                var user = await _context.Users.FirstOrDefaultAsync(x => x.Email == request.Email);
                if (user == null) return null;

                user.FirstName = request.FirstName;
                user.LastName = request.LastName;
                user.UserName = request.UserName ?? user.UserName;
                user.DateOfBirth = request.DateOfBirth;
                user.Address = request.Address;

                if (!string.IsNullOrEmpty(user.ProfilePictureUrl) && user.ProfilePictureUrl.Length > 0)
                {
                    if (request.ProfilePictureUrl != null)
                    {
                        var uploadUrl = await _cloudinaryUploader.UploadImage(request.ProfilePictureUrl);
                        if (!string.IsNullOrEmpty(uploadUrl))
                        {
                            user.ProfilePictureUrl = uploadUrl;
                        }
                    }
                }

                await _context.SaveChangesAsync();

                return user;
            }
            catch
            {
                // Log the exception (ex) as needed
                throw new GlobalException("An error occurred while updating the user profile.");
            }
        }
        else
        {
            return null;
        }
    }

    public async Task<Users?> UpdateUserPassword(Guid userId, string oldPassword, string newPassword)
    {
        var user = await _context.Users.FindAsync(userId);
        if (user == null)
        {
            throw new GlobalException("User not found.");
        }
        var result = await _userManager.ChangePasswordAsync(user, oldPassword, newPassword);
        if (result.Succeeded)
        {
            await _context.SaveChangesAsync();
            return user;
        }
        else
        {
            throw new GlobalException("Change password" + string.Join(", ", result.Errors.Select(e => e.Description)));
        }
    }
}