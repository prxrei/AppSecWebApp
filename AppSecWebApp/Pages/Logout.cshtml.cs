using AppSecWebApp.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Http;

namespace AppSecWebApp.Pages
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly UserManager<ApplicationUser> userManager;

        public LogoutModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
        }

        public void OnGet() 
        { 
        }

        public async Task<IActionResult> OnPostLogoutAsync()
        {
            // Retrieve user ID from the session
            var userId = HttpContext.Session.GetString("UserId");

            // Clear session items
            HttpContext.Session.Remove("UserId");
            HttpContext.Session.Remove("UserName");
            HttpContext.Session.Remove("SessionIdentifier");

            // Remove the user's unique identifier from the database
            if (!string.IsNullOrEmpty(userId))
            {
                var user = await userManager.FindByIdAsync(userId);
                if (user != null)
                {
                    user.UniqueIdentifier = "";
                    await userManager.UpdateAsync(user);
                }
            }

            // Sign out the user
            await signInManager.SignOutAsync();

            // Remove the AuthToken cookie
            Response.Cookies.Delete("AuthToken");

            return RedirectToPage("Login");
        }

        public async Task<IActionResult> OnPostDontLogoutAsync()
        {
            return RedirectToPage("Index");
        }
    }
}
