using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace AppSecWebApp.ViewModels
{
    public class Register
    {
		[Required]
        [RegularExpression(@"^[A-Za-z\s]+$", ErrorMessage = "Full Name does not meet the website's requirements")]
        public string FullName { get; set; }

		[Required]
        [RegularExpression(@"\b(?:\d[-]*?){15,16}\b", ErrorMessage = "Please enter a VALID Credit Card Number")]
        [DataType(DataType.CreditCard)]
		public string CreditCardNumber { get; set; }

		[Required]
		public string Gender { get; set; }

		[Required]
        [RegularExpression(@"^\d+$", ErrorMessage = "Please enter a VALID Mobile Number.")]
        [DataType(DataType.PhoneNumber)]
		public string MobileNumber { get; set; }

		[Required]
        [RegularExpression(@"^[A-Za-z0-9\s#-]*$", ErrorMessage = "Please enter a VALID delivery address.")]
        public string DeliveryAddress { get; set; }

		[Required]
        [DataType(DataType.EmailAddress)]
        [RegularExpression(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ErrorMessage = "Please enter a VALID email address.")]
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
		public string AboutMe { get; set; }



	}
}
