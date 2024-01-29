using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;
using AppSecWebApp.ViewModels;
using AppSecWebApp.Model;
using IdentityUser = Microsoft.AspNetCore.Identity.IdentityUser;

namespace AppSecWebApp.Pages
{
    public class LoginModel : PageModel
    {
		[BindProperty]
		public Login LModel { get; set; }

		private readonly SignInManager<ApplicationUser> signInManager;
        private readonly ILogger<LoginModel> _logger;
        public LoginModel(SignInManager<ApplicationUser> signInManager, ILogger<LoginModel> logger)
		{
			this.signInManager = signInManager;
            _logger = logger;
        }
		public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (ModelState.IsValid)
            {
                var identityResult = await signInManager.PasswordSignInAsync(LModel.Email, LModel.Password, LModel.RememberMe, false);
                if (identityResult.Succeeded)
                {
                    var user = await signInManager.UserManager.FindByEmailAsync(LModel.Email);

                    if (user != null)
                    {
                        // Store user-related data in session
                        HttpContext.Session.SetString("UserId", user.Id);
                        HttpContext.Session.SetString("UserName", user.UserName);
                        HttpContext.Session.SetString("KeepSessionAlive", "true");
                        // Add other user-related data to session as needed
                    }

                    _logger.LogInformation($"UserId: {HttpContext.Session.GetString("UserId")}");
                    _logger.LogInformation($"UserName: {HttpContext.Session.GetString("UserName")}");

                    // Redirect to the absolute path of the Index page
                    return RedirectToPage("/Index");
                }
                ModelState.AddModelError("", "Username or Password incorrect");
            }
            return Page();
        }


    }
}
