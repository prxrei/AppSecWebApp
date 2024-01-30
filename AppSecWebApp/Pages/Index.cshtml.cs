using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using AppSecWebApp.Model;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using System.Text.Encodings.Web;

namespace AppSecWebApp.Pages
{
	[Authorize]
	public class IndexModel : PageModel
	{
		private readonly ILogger<IndexModel> _logger;
		private readonly SignInManager<ApplicationUser> signInManager;
		private readonly UserManager<ApplicationUser> _userManager;
		private readonly IHttpContextAccessor _httpContextAccessor;

		public IndexModel(ILogger<IndexModel> logger, SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, IHttpContextAccessor httpContextAccessor)
		{
			_logger = logger;
			_userManager = userManager;
			this.signInManager = signInManager;
			_httpContextAccessor = httpContextAccessor;
		}

		public ApplicationUser CurrentUser { get; set; }

		public async Task OnGetAsync()
		{
			var dataProtectionProvider = DataProtectionProvider.Create("Encrypt");
			var protecting = dataProtectionProvider.CreateProtector("Key");
			CurrentUser = await _userManager.GetUserAsync(User);
			var httpContext = _httpContextAccessor.HttpContext;

            if (!User.Identity.IsAuthenticated)
			{
				Response.Redirect("/Login");
				await signInManager.SignOutAsync();
				CurrentUser.UniqueIdentifier = "";
				return;
			}

			// Check for session variables
			if (httpContext.Session.GetString("UserId") == null ||
				httpContext.Session.GetString("UserName") == null ||
				httpContext.Session.GetString("KeepSessionAlive") == null)
			{
				Response.Redirect("/Login"); // Redirect to the login page if session variables are not set
				await signInManager.SignOutAsync();
				CurrentUser.UniqueIdentifier = "";
				return;
			}

			// Check for AuthToken in session and cookie
			var sessionAuthToken = httpContext.Session.GetString("AuthToken");
			var cookieAuthToken = httpContext.Request.Cookies["AuthToken"];

			if (sessionAuthToken == null || cookieAuthToken == null || sessionAuthToken != cookieAuthToken)
			{
				Response.Redirect("/Login");
				await signInManager.SignOutAsync();
				CurrentUser.UniqueIdentifier = "";
				return;
			}

			// Check if the stored session identifier in the user's session matches the one in the secure cookie
			string storedSessionIdentifier = httpContext.Session.GetString("SessionIdentifier");
			string cookieSessionIdentifier = httpContext.Request.Cookies["SessionIdentifierCookie"];

			if (storedSessionIdentifier != cookieSessionIdentifier)
			{
				Response.Redirect("/Login");
				await signInManager.SignOutAsync();
				CurrentUser.UniqueIdentifier = "";
				return;
			}

			// HTML encode the unprotected user information
			CurrentUser.FullName = HtmlEncoder.Default.Encode(protecting.Unprotect(CurrentUser?.FullName) ?? string.Empty);
			CurrentUser.CreditCardNumber = HtmlEncoder.Default.Encode(protecting.Unprotect(CurrentUser?.CreditCardNumber) ?? string.Empty);
			CurrentUser.Gender = HtmlEncoder.Default.Encode(protecting.Unprotect(CurrentUser?.Gender) ?? string.Empty);
			CurrentUser.MobileNumber = HtmlEncoder.Default.Encode(protecting.Unprotect(CurrentUser?.MobileNumber) ?? string.Empty);
			CurrentUser.DeliveryAddress = HtmlEncoder.Default.Encode(protecting.Unprotect(CurrentUser?.DeliveryAddress) ?? string.Empty);
			CurrentUser.AboutMe = HtmlEncoder.Default.Encode(protecting.Unprotect(CurrentUser?.AboutMe) ?? string.Empty);
			CurrentUser.PhotoPath = HtmlEncoder.Default.Encode(protecting.Unprotect(CurrentUser.PhotoPath) ?? string.Empty);

			// Log the session ID
			var sessionId = httpContext.Session.Id;
			_logger.LogInformation($"Session ID: {sessionId}");

			// Reset the session timeout by updating session variables
			httpContext.Session.GetString("UserId");
			httpContext.Session.GetString("UserName");
			httpContext.Session.GetString("KeepSessionAlive");

			// Access the UniqueIdentifier property
			string uniqueIdentifier = CurrentUser?.UniqueIdentifier ?? string.Empty;
			_logger.LogInformation($"UniqueIdentifier: {uniqueIdentifier}");
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
