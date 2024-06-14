using Microsoft.AspNetCore.Identity;


namespace Web.Service.Models.Authentication.User
{
    public class CreateUserResponse
    {
        public string Token { get; set; } = null!;
        public IdentityUser User { get; set; } = null!;
    }
}
