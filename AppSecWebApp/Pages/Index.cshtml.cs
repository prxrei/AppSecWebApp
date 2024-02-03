using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using AppSecWebApp.Model;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.Net;

namespace AppSecWebApp.Pages
{
	[Authorize]
	public class IndexModel : PageModel
	{
		private readonly ILogger<IndexModel> _logger;
		private readonly SignInManager<ApplicationUser> signInManager;
		private readonly UserManager<ApplicationUser> _userManager;
		private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IConfiguration _configuration;

        public IndexModel(ILogger<IndexModel> logger, SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, IHttpContextAccessor httpContextAccessor, IConfiguration configuration)
		{
			_logger = logger;
			_userManager = userManager;
			this.signInManager = signInManager;
			_httpContextAccessor = httpContextAccessor;
            _configuration = configuration;
        }

		public ApplicationUser CurrentUser { get; set; }
        public int sessionTimeout { get; private set; }

        [ValidateAntiForgeryToken]
        public async Task OnGetAsync()
		{
			var dataProtectionProvider = DataProtectionProvider.Create("Encrypt");
			var protecting = dataProtectionProvider.CreateProtector("Key");
			CurrentUser = await _userManager.GetUserAsync(User);
			var httpContext = _httpContextAccessor.HttpContext;
            sessionTimeout = _configuration.GetValue<int>("Session:IdleTimeoutInSeconds");
			_logger.LogInformation($"sessionTimeout: {sessionTimeout}");

			if (!User.Identity.IsAuthenticated)
			{
                HttpContext.Session.Remove("UserId");
                HttpContext.Session.Remove("UserName");
                HttpContext.Session.Remove("SessionIdentifier");
                HttpContext.Session.Remove("AuthToken");
                await signInManager.SignOutAsync();
                Response.Cookies.Delete("AuthToken");
                Response.Cookies.Delete("SessionIdentifierCookie");
                Response.Redirect("/Login");
				return;
			}

			// Check for session variables
			if (httpContext.Session.GetString("UserId") == null ||
				httpContext.Session.GetString("UserName") == null ||
				httpContext.Session.GetString("KeepSessionAlive") == null)
			{
                HttpContext.Session.Remove("UserId");
                HttpContext.Session.Remove("UserName");
                HttpContext.Session.Remove("SessionIdentifier");
                HttpContext.Session.Remove("AuthToken");
                await signInManager.SignOutAsync();
                Response.Cookies.Delete("AuthToken");
                Response.Cookies.Delete("SessionIdentifierCookie");
                Response.Redirect("/Login");
                return;
			}

			// Check for AuthToken in session and cookie
			var sessionAuthToken = httpContext.Session.GetString("AuthToken");
			var cookieAuthToken = httpContext.Request.Cookies["AuthToken"];

			if (sessionAuthToken == null || cookieAuthToken == null || sessionAuthToken != cookieAuthToken)
			{
                HttpContext.Session.Remove("UserId");
                HttpContext.Session.Remove("UserName");
                HttpContext.Session.Remove("SessionIdentifier");
                HttpContext.Session.Remove("AuthToken");
                await signInManager.SignOutAsync();
                Response.Cookies.Delete("AuthToken");
                Response.Cookies.Delete("SessionIdentifierCookie");
                Response.Redirect("/Login");
				return;
			}

			// Check if the stored session identifier in the user's session matches the one in the secure cookie
			string storedSessionIdentifier = httpContext.Session.GetString("SessionIdentifier");
			string cookieSessionIdentifier = httpContext.Request.Cookies["SessionIdentifierCookie"];

			if (storedSessionIdentifier != cookieSessionIdentifier)
			{
                HttpContext.Session.Remove("UserId");
                HttpContext.Session.Remove("UserName");
                HttpContext.Session.Remove("SessionIdentifier");
                HttpContext.Session.Remove("AuthToken");
                await signInManager.SignOutAsync();
                Response.Cookies.Delete("AuthToken");
                Response.Cookies.Delete("SessionIdentifierCookie");
                Response.Redirect("/Login");
				return;
			}

			// HTML encode the unprotected user information
			CurrentUser.FullName = HtmlEncoder.Default.Encode(protecting.Unprotect(CurrentUser?.FullName) ?? string.Empty);
			CurrentUser.CreditCardNumber = HtmlEncoder.Default.Encode(protecting.Unprotect(CurrentUser?.CreditCardNumber) ?? string.Empty);
			CurrentUser.Gender = HtmlEncoder.Default.Encode(protecting.Unprotect(CurrentUser?.Gender) ?? string.Empty);
			CurrentUser.MobileNumber = HtmlEncoder.Default.Encode(protecting.Unprotect(CurrentUser?.MobileNumber) ?? string.Empty);
			CurrentUser.DeliveryAddress = HtmlEncoder.Default.Encode(protecting.Unprotect(CurrentUser?.DeliveryAddress) ?? string.Empty);
			CurrentUser.AboutMe = WebUtility.HtmlDecode(protecting.Unprotect(CurrentUser?.AboutMe) ?? string.Empty);
			CurrentUser.PhotoPath = HtmlEncoder.Default.Encode(protecting.Unprotect(CurrentUser.PhotoPath) ?? string.Empty);

			// Log the session ID
			var sessionId = httpContext.Session.Id;
			_logger.LogInformation($"Session ID: {sessionId}");

			// Reset the session timeout by updating session variables
			httpContext.Session.GetString("UserId");
			httpContext.Session.GetString("UserName");
			httpContext.Session.GetString("KeepSessionAlive");

            var timeSinceLastPasswordChange = DateTime.UtcNow - CurrentUser.PasswordChangedDate;

            // Check if the user should be redirected to change their password
            if (timeSinceLastPasswordChange > TimeSpan.FromMinutes(30) && User.Identity.IsAuthenticated)
            {
                // Redirect to the ChangeThePwd page
                Response.Redirect("/ChangeThePwd");
                return;
            }
        }

		public string DisplayImage()
		{
			if (CurrentUser != null && !string.IsNullOrEmpty(CurrentUser.PhotoPath))
			{
				return CurrentUser.PhotoPath;
			}

			// Default profile image path if the user doesn't have a photo
			return "/images/default-profile.jpg";
		}
	}
}
