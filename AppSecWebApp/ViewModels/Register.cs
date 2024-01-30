using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace AppSecWebApp.ViewModels
{
    public class Register
    {
		[Required(ErrorMessage = "Full Name Required")]
		public string FullName { get; set; }

		[Required(ErrorMessage = "Credit Card Number Required")]
		[DataType(DataType.CreditCard)]
		public string CreditCardNumber { get; set; }

		[Required(ErrorMessage = "Gender Required")]
		public string Gender { get; set; }

		[Required(ErrorMessage = "Mobile Number Required")]
		[DataType(DataType.PhoneNumber)]
		public string MobileNumber { get; set; }

		[Required(ErrorMessage = "Delivery Address Required")]
		public string DeliveryAddress { get; set; }

		[Required]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }

		[Required]
		[DataType(DataType.Password)]
		[RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{12,}$", ErrorMessage = "Password must be at least 12 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")]
		public string Password { get; set; }

		[Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Password and confirmation password does not match")]
        public string ConfirmPassword { get; set; }

		[Required]
		[DataType(DataType.Upload)]
		public IFormFile? Photo { get; set; }

		[Required]
		public string? AboutMe { get; set; }



	}
}
