using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AppSecWebApp.Pages
{
    public class LockedOut_Model : PageModel
    {
        public DateTimeOffset LockoutEnd { get; set; }

        public void OnGet()
        {
            // Retrieve the current user
            var user = HttpContext.User.Identity.Name; // Assuming you are using the user's username or email for identification

            // Retrieve the LockoutEnd value from the user
            var userManager = HttpContext.RequestServices.GetService(typeof(UserManager<IdentityUser>)) as UserManager<IdentityUser>;
            var currentUser = userManager.FindByNameAsync(user).Result;
            LockoutEnd = currentUser.LockoutEnd ?? DateTimeOffset.Now; // If LockoutEnd is null, set to current time
        }
    }
}
