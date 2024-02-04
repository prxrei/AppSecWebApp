using AppSecWebApp.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Http;

namespace AppSecWebApp.Pages
{
    [Authorize]
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public LogoutModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, IHttpContextAccessor httpContextAccessor)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task OnGetAsync()
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (!User.Identity.IsAuthenticated)
            {
                httpContext.Session.Remove("UserId");
                httpContext.Session.Remove("UserName");
                httpContext.Session.Remove("SessionIdentifier");
                httpContext.Session.Remove("AuthToken");
                await _signInManager.SignOutAsync();
                Response.Cookies.Delete("AuthTokenCookie");
                Response.Cookies.Delete("SessionIdentifierCookie");
                Response.Redirect("/Login");
                return;
            }

            if (httpContext.Session.GetString("UserId") == null ||
                httpContext.Session.GetString("UserName") == null ||
                httpContext.Session.GetString("KeepSessionAlive") == null)
            {
                httpContext.Session.Remove("UserId");
                httpContext.Session.Remove("UserName");
                httpContext.Session.Remove("SessionIdentifier");
                httpContext.Session.Remove("AuthToken");
                await _signInManager.SignOutAsync();
                Response.Cookies.Delete("AuthTokenCookie");
                Response.Cookies.Delete("SessionIdentifierCookie");
                Response.Redirect("/Login");
                return;
            }

            var sessionAuthToken = httpContext.Session.GetString("AuthToken");
            var cookieAuthToken = httpContext.Request.Cookies["AuthTokenCookie"];

            if (sessionAuthToken == null || cookieAuthToken == null || sessionAuthToken != cookieAuthToken)
            {
                httpContext.Session.Remove("UserId");
                httpContext.Session.Remove("UserName");
                httpContext.Session.Remove("SessionIdentifier");
                httpContext.Session.Remove("AuthTokenCookie");
                await _signInManager.SignOutAsync();
                Response.Cookies.Delete("AuthTokenCookie");
                Response.Cookies.Delete("SessionIdentifierCookie");
                Response.Redirect("/Login");
                return;
            }

            string storedSessionIdentifier = httpContext.Session.GetString("SessionIdentifier");
            string cookieSessionIdentifier = httpContext.Request.Cookies["SessionIdentifierCookie"];

            if (storedSessionIdentifier != cookieSessionIdentifier)
            {
                httpContext.Session.Remove("UserId");
                httpContext.Session.Remove("UserName");
                httpContext.Session.Remove("SessionIdentifier");
                httpContext.Session.Remove("AuthToken");
                await _signInManager.SignOutAsync();
                Response.Cookies.Delete("AuthTokenCookie");
                Response.Cookies.Delete("SessionIdentifierCookie");
                Response.Redirect("/Login");
                return;
            }
        }

        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostLogoutAsync()
        {
            var userId = HttpContext.Session.GetString("UserId");

            HttpContext.Session.Remove("UserId");
            HttpContext.Session.Remove("UserName");
            HttpContext.Session.Remove("SessionIdentifier");
            HttpContext.Session.Remove("AuthToken");

            await _signInManager.SignOutAsync();

            Response.Cookies.Delete("AuthToken");
            Response.Cookies.Delete("SessionIdentifierCookie");

            return RedirectToPage("Login");
        }

        public async Task<IActionResult> OnPostDontLogoutAsync()
        {
            return RedirectToPage("Index");
        }
    }
}
