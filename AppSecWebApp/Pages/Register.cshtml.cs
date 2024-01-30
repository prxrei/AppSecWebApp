using AppSecWebApp.Model;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using AppSecWebApp.ViewModels;
using NanoidDotNet;
using System.Text.Encodings.Web;


namespace AppSecWebApp.Pages
{
	public class RegisterModel : PageModel
	{
		private readonly UserManager<ApplicationUser> userManager;
		private readonly SignInManager<ApplicationUser> signInManager;
		private readonly IWebHostEnvironment _environment;
        private readonly IHttpContextAccessor _httpContextAccessor;

        [BindProperty]
		public Register RModel { get; set; }

		public RegisterModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IWebHostEnvironment environment, IHttpContextAccessor httpContextAccessor)
		{
			this.userManager = userManager;
			this.signInManager = signInManager;
			_environment = environment;
			_httpContextAccessor = httpContextAccessor;
		}

		public void OnGet()
		{
		}

		[ValidateAntiForgeryToken]
		public async Task<IActionResult> OnPostAsync()
		{
			if (ModelState.IsValid)
			{
				var dataProtectionProvider = DataProtectionProvider.Create("Encrypt");
				var protecting = dataProtectionProvider.CreateProtector("Key");


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
					FullName = HtmlEncoder.Default.Encode(protecting.Protect(RModel.FullName)),
					CreditCardNumber = HtmlEncoder.Default.Encode(protecting.Protect(RModel.CreditCardNumber)),
					Gender = HtmlEncoder.Default.Encode(protecting.Protect(RModel.Gender)),
					MobileNumber = HtmlEncoder.Default.Encode(protecting.Protect(RModel.MobileNumber)),
					DeliveryAddress = HtmlEncoder.Default.Encode(protecting.Protect(RModel.DeliveryAddress)),
					AboutMe = HtmlEncoder.Default.Encode(protecting.Protect(RModel.AboutMe)),
					UniqueIdentifier = ""
				};


				if (RModel.Photo != null)
				{
					var id = Nanoid.Generate(size: 10);
					var filename = id + Path.GetExtension(RModel.Photo.FileName);
					var imagePath = Path.Combine(_environment.ContentRootPath, @"wwwroot/Profile", filename);
					using var fileStream = new FileStream(imagePath, FileMode.Create);
					RModel.Photo.CopyTo(fileStream);
					user.PhotoPath = protecting.Protect($"/Profile/{filename}");
				}


				var result = await userManager.CreateAsync(user, RModel.Password);

				if (result.Succeeded)
				{
                    await signInManager.SignInAsync(user, false);
                    _httpContextAccessor.HttpContext.Session.SetString("UserId", user.Id);
                    _httpContextAccessor.HttpContext.Session.SetString("UserName", user.UserName);
                    return RedirectToPage("Login");
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