using Web.Service.Models.Authentication.SignUp;
using Web.Service.Models;

namespace Web.Service.Services
{
    public interface IUserManagement
    {
        Task<ApiResponse<string>> CreateUserWithTokenAsync(RegisterUser registerUser);

    }
}
