using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Web.Service.Models;
using Web.Service.Services;
using WebApiAuth.Models;
using WebApiAuth.Models.Authentication.Login;
using WebApiAuth.Models.Authentication.SignUp;

namespace WebApiAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;

        public AuthenticationController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager, IEmailService emailService,
            SignInManager<IdentityUser> signInManager
            , IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _configuration = configuration;
            _signInManager = signInManager;
        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser, string role)
        {
            // Check user exist
            var userExists = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExists != null)
            {
                return StatusCode(StatusCodes.Status403Forbidden, new Response { Status = "Error", Message = "User already exists!" });
            }

            // Add the user in the database
            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.UserName,
                TwoFactorEnabled = true
            };

            if (await _roleManager.RoleExistsAsync(role))
            {
                var result = await _userManager.CreateAsync(user, registerUser.Password);

                if (!result.Succeeded)
                {
                    StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Failed to create the user!" });
                }

                // Assign a role
                await _userManager.AddToRoleAsync(user, role);

                // add token to verify the account
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { token, email = user.Email }, Request.Scheme);
                var message = new Message(new string[] { user.Email! }, "Email confirmation link", confirmationLink!);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status201Created, new Response { Status = "Success", Message = "User created successfully & account confirmation email sent.!" });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Roles doesnot exist. Failed to create the user!" });
            }
        }

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = "Email verified successfully!" });
                }
            }
            return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "This user doesnot exist!" });
        }


        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            // check the user...
            var user = await _userManager.FindByNameAsync(loginModel.Username);

            if (user.TwoFactorEnabled)
            {
                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);


                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                var message = new Message(new string[] { user.Email! }, "OTP Confirmation", token);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status201Created,
                    new Response { Status = "Success", Message = $"We have sent an OTP to your Email {user.Email}" });

            }

            // check the password

            if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
            {
                // claim list creation
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                // add roles to the list
                var userRoles = await _userManager.GetRolesAsync(user);

                foreach (var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }

                

                // generate the token with the claims
                var jwtToken = GetToken(authClaims);

                // return the token
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    expiration = jwtToken.ValidTo,
                    user = user.UserName
                });
            }

            return Unauthorized();
        }

        [HttpPost]
        [Route("login-2FA")]
        public async Task<IActionResult> LoginWithOTP(string code, string username)
        {
            var user = await _userManager.FindByNameAsync(username);

            var signIn = await _signInManager.TwoFactorSignInAsync("Email", code, false, false);
            if (signIn.Succeeded)
            {
                if (user != null)
                {
                    // claim list creation
                    var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                    // add roles to the list
                    var userRoles = await _userManager.GetRolesAsync(user);

                    foreach (var role in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }



                    // generate the token with the claims
                    var jwtToken = GetToken(authClaims);

                    // return the token
                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        expiration = jwtToken.ValidTo,
                        user = user.UserName
                    });
                }

            }
            return StatusCode(StatusCodes.Status404NotFound,
                new Response { Status = "Fail", Message = "Invalid  token" });
        }

        [HttpPost]
        [Route("Forgot-Password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([Required] string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var forgotPasswordLink = Url.Action(nameof(ResetPassword),"Authentication", new { token, email=user.Email}, Request.Scheme);

                var message = new Message(new string[] { user.Email! }, "Forgot password link", forgotPasswordLink!);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = "The reset password link has been delivered to your email." });
            }

            return StatusCode(StatusCodes.Status400BadRequest,
                  new Response { Status = "Error", Message = "Couldn't send the reset link." });
        }

        [HttpGet("reset-password")]
        public async Task<IActionResult> ResetPassword(string token, string email)
        {
            var model = new ResetPassword
            {
                Token = token,
                Email = email
            };

            return Ok(new
            {
                model
            });
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            var user  = await _userManager.FindByEmailAsync(resetPassword.Email);

            if(user != null)
            {
                var resetPassResult = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);
                if(!resetPassResult.Succeeded)
                {
                    foreach(var error in resetPassResult.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }
                    return Ok(ModelState);
                }
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = "Password has been changed" });
            }
            return StatusCode(StatusCodes.Status400BadRequest,
                        new Response { Status = "Error", Message = "Error occurred while resetting your password!" });

        }



        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddDays(2),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }

    }
}
