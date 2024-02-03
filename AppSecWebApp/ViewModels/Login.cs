using System.ComponentModel.DataAnnotations;

namespace AppSecWebApp.ViewModels
{
    public class Login
    {
        [Required(ErrorMessage = "Email is required")]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }
        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        public bool RememberMe { get; set; }
        public string Token { get; set; }
    }
}
