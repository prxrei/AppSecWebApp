using AppSecWebApp.Model;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using AppSecWebApp.ViewModels;
using NanoidDotNet;


namespace AppSecWebApp.Pages
{
	public class RegisterModel : PageModel
	{
		private readonly UserManager<ApplicationUser> userManager;
		private readonly SignInManager<ApplicationUser> signInManager;
		private readonly IWebHostEnvironment _environment;

		[BindProperty]
		public Register RModel { get; set; }

		public RegisterModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IWebHostEnvironment environment)
		{
			this.userManager = userManager;
			this.signInManager = signInManager;
			_environment = environment;
		}

		public void OnGet()
		{
		}

		public async Task<IActionResult> OnPostAsync()
		{
			if (ModelState.IsValid)
			{
				var dataProtectionProvider = DataProtectionProvider.Create("Encrypt");
				var protector = dataProtectionProvider.CreateProtector("Key");


				var emailexist = await userManager.FindByEmailAsync(RModel.Email);
				if (emailexist != null)
				{
					ModelState.AddModelError("RModel.EmailAddress", "Email address already registered, please choose another Email Address.");
					return Page();
				}


				var user = new ApplicationUser()
				{
					UserName = RModel.Email,
					Email = RModel.Email,
					FullName = protector.Protect(RModel.FullName),
					CreditCardNumber = protector.Protect(RModel.CreditCardNumber),
					Gender = protector.Protect(RModel.Gender),
					MobileNumber = protector.Protect(RModel.MobileNumber),
					DeliveryAddress = protector.Protect(RModel.DeliveryAddress),
					AboutMe = protector.Protect(RModel.AboutMe),
				};

				if (RModel.Photo != null)
				{
					var id = Nanoid.Generate(size: 10);
					var filename = id + Path.GetExtension(RModel.Photo.FileName);
					var imagePath = Path.Combine(_environment.ContentRootPath, @"wwwroot/Profile", filename);
					using var fileStream = new FileStream(imagePath, FileMode.Create);
					RModel.Photo.CopyTo(fileStream);
					user.PhotoPath = protector.Protect($"/Profile/{filename}");
				}


				var result = await userManager.CreateAsync(user, RModel.Password);

				if (result.Succeeded)
				{
					await signInManager.SignInAsync(user, false);
					return RedirectToPage("Index");
				}

				foreach (var error in result.Errors)
				{
					ModelState.AddModelError("", error.Description);
				}
			}

			return Page();
		}
	}
}