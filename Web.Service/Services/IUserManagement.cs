using Web.Service.Models.Authentication.SignUp;
using Web.Service.Models;
using Microsoft.AspNetCore.Identity;
using Web.Service.Models.Authentication.User;

namespace Web.Service.Services
{
    public interface IUserManagement
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="registerUser"></param>
        /// <returns></returns>

        Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser registerUser);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="role"></param>
        /// <returns></returns>
        Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, IdentityUser user);

    }
}
