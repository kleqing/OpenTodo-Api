using OpenTodo.Domain.Contracts.Request.User;
using OpenTodo.Domain.Entities;

namespace OpenTodo.Domain.Interfaces;

public interface IUserRepository
{
    Task<Users?> GetUserById(Guid userId);
    Task<Users?> UpdateUserProfile(UserProfileRequest request);
    Task<Users?> UpdateUserPassword(Guid userId, string oldPassword, string newPassword);
}