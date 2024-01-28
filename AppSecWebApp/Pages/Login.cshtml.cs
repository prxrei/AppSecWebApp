using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
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
		public LoginModel(SignInManager<ApplicationUser> signInManager)
		{
			this.signInManager = signInManager;
		}
		public void OnGet()
        {
        }

		public async Task<IActionResult> OnPostAsync()
		{
			if (ModelState.IsValid)
			{
				var identityResult = await signInManager.PasswordSignInAsync(LModel.Email, LModel.Password,LModel.RememberMe, false);
				if (identityResult.Succeeded)
				{
					var claims = new List<Claim>
					{
						new Claim(ClaimTypes.Name, "c@c.com"),
						new Claim(ClaimTypes.Email, "c@c.com"),
					};
					var i = new ClaimsIdentity(claims, "Cookie");
					ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal(i);
                    await HttpContext.SignInAsync("Cookie", claimsPrincipal);
					return RedirectToPage("Index");
				}
				ModelState.AddModelError("", "Username or Password incorrect");
			}
			return Page();
		}
	}
}
