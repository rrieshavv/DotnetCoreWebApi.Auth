using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Org.BouncyCastle.Asn1.Ocsp;
using Web.Service.Models;
using Web.Service.Models.Authentication.SignUp;

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


        public async Task<ApiResponse<string>> CreateUserWithTokenAsync(RegisterUser registerUser)
        {
            // Check user exist
            var userExists = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExists != null)
            {
                return new ApiResponse<string> { isSuccess = false, StatusCode = 403, Message = "User already exists"};
            }

            // Add the user in the database
            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.UserName,
                TwoFactorEnabled = true
            };

            if (await _roleManager.RoleExistsAsync(registerUser.Role))
            {
                var result = await _userManager.CreateAsync(user, registerUser.Password);

                if (!result.Succeeded)
                {
                return new ApiResponse<string> { isSuccess = false, StatusCode = 500, Message = "User failed to create."};
                }

                // Assign a role
                await _userManager.AddToRoleAsync(user, registerUser.Role);

                // add token to verify the account
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                //var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { token, email = user.Email }, Request.Scheme);
                //var message = new Message(new string[] { user.Email! }, "Email confirmation link", confirmationLink!);
                //_emailService.SendEmail(message);

                return new ApiResponse<string> { isSuccess = true, StatusCode = 201, Message = "User created successfully.", Response=token };
            }
            else
            {
                return new ApiResponse<string> { isSuccess = false, StatusCode = 500, Message = "Entered Role doesn't exist." };

            }
        }
    }
}
