using Microsoft.AspNetCore.Identity;

namespace AppSecWebApp.Model
{
	public class ApplicationUser : IdentityUser
	{
		public string FullName { get; set; }
		public string CreditCardNumber { get; set; }
		public string Gender { get; set; }
		public string MobileNumber { get; set; }
		public string DeliveryAddress { get; set; }
		public string? PhotoPath { get; set; }
		public string? AboutMe { get; set; }
		public DateTime? LastLogin { get; set; }
		public DateTime? PasswordChangedDate { get; set; }
		public string? PasswordHashHistory { get; set; }
	}
}
