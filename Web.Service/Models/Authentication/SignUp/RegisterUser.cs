using System.ComponentModel.DataAnnotations;

namespace Web.Service.Models.Authentication.SignUp
{
    public class RegisterUser
    {
        [Required(ErrorMessage = "User Name is required.")]
        public string? UserName { get; set; }

        [Required(ErrorMessage = "Email is required.")]
        public string? Email { get; set; }

        [Required(ErrorMessage = "Password is required.")]
        public string? Password { get; set; }

        [Required(ErrorMessage = "Role is required.")]
        public List<string>? Roles { get; set; }
    }
}
