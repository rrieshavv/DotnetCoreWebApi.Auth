using MailKit.Net.Imap;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Org.BouncyCastle.Asn1.Ocsp;
using Web.Service.Models;
using Web.Service.Models.Authentication.Login;
using Web.Service.Models.Authentication.SignUp;
using Web.Service.Models.Authentication.User;

namespace Web.Service.Services
{

    public class UserManagement : IUserManagement
    {

        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserManagement(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
        }

        public async Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, IdentityUser user)
        {
            var assignedRole = new List<string>();
            foreach (var role in roles)
            {
                if (await _roleManager.RoleExistsAsync(role))
                {
                    if (!await _userManager.IsInRoleAsync(user, role))
                    {
                        await _userManager.AddToRoleAsync(user, role);
                        assignedRole.Add(role);
                    }
                }
            }
            return new ApiResponse<List<string>>
            {
                isSuccess = true,
                StatusCode = 200,
                Message = "Roles has been assigned successfully.",
                Response = assignedRole
            };
        }

        public async Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser registerUser)
        {
            // Check user exist
            var userExists = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExists != null)
            {
                return new ApiResponse<CreateUserResponse> { isSuccess = false, StatusCode = 403, Message = "User already exists" };
            }

            // Add the user in the database
            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.UserName,
                TwoFactorEnabled = true
            };

            var result = await _userManager.CreateAsync(user, registerUser.Password!);

            if (result.Succeeded)
            {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                return new ApiResponse<CreateUserResponse> { Response = new CreateUserResponse() { User = user, Token = token }, isSuccess = true, StatusCode = 201, Message = "User Created." };
            }
            else
            {
                return new ApiResponse<CreateUserResponse> { isSuccess = false, StatusCode = 500, Message = "User failed to create." };
            }
        }

        public async Task<ApiResponse<LoginOtpResponse>> GetOTPByLoginAsync(LoginModel loginModel)
        {
            var user = await _userManager.FindByNameAsync(loginModel.Username);
            if(user == null)
            {
                return new ApiResponse<LoginOtpResponse>
                {
                    isSuccess = false,
                    StatusCode = 404,
                    Message = $"User doesn't exist!"
                };
            }

            await _signInManager.SignOutAsync();
            await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);
            if(user.TwoFactorEnabled)
            {
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                return new ApiResponse<LoginOtpResponse>
                {
                    Response = new LoginOtpResponse()
                    {
                        Token = token,
                        User = user,
                        IsTwoFactorEnable = user.TwoFactorEnabled
                    },
                    isSuccess = true,
                    StatusCode = 200,
                    Message = $"OTP sent to {user.Email} successfully"
                };
            }
            return new ApiResponse<LoginOtpResponse>
            {
                Response = new LoginOtpResponse()
                {
                    Token = string.Empty,
                    User = user,
                    IsTwoFactorEnable = user.TwoFactorEnabled
                },
                isSuccess = true,
                StatusCode = 200,
                Message = $"2FA is not enabled!"
            };
        }
    }
}
