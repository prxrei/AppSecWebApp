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
using Microsoft.Extensions.Options;

namespace AppSecWebApp.Pages
{
	[Authorize]
	public class IndexModel : PageModel
	{
		private readonly ILogger<IndexModel> _logger;
		private readonly SignInManager<ApplicationUser> _signInManager;
		private readonly UserManager<ApplicationUser> _userManager;
		private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IConfiguration _configuration;

        public IndexModel(ILogger<IndexModel> logger, SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, IHttpContextAccessor httpContextAccessor, IConfiguration configuration)
		{
			_logger = logger;
			_userManager = userManager;
			_signInManager = signInManager;
			_httpContextAccessor = httpContextAccessor;
            _configuration = configuration;
        }

		public ApplicationUser CurrentUser { get; set; }

        public double SessionTimeout { get; private set; }

        [ValidateAntiForgeryToken]
        public async Task OnGetAsync()
		{
			var dataProtectionProvider = DataProtectionProvider.Create("Encrypt");
			var protecting = dataProtectionProvider.CreateProtector("Key");
			CurrentUser = await _userManager.GetUserAsync(User);
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

			if (httpContext.Session.GetString("UserId") == null || httpContext.Session.GetString("UserName") == null ||httpContext.Session.GetString("KeepSessionAlive") == null)
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
                httpContext.Session.Remove("AuthToken");
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

			CurrentUser.FullName = HtmlEncoder.Default.Encode(protecting.Unprotect(CurrentUser?.FullName) ?? string.Empty);
			CurrentUser.CreditCardNumber = HtmlEncoder.Default.Encode(protecting.Unprotect(CurrentUser?.CreditCardNumber) ?? string.Empty);
			CurrentUser.Gender = HtmlEncoder.Default.Encode(protecting.Unprotect(CurrentUser?.Gender) ?? string.Empty);
			CurrentUser.MobileNumber = HtmlEncoder.Default.Encode(protecting.Unprotect(CurrentUser?.MobileNumber) ?? string.Empty);
			CurrentUser.DeliveryAddress = HtmlEncoder.Default.Encode(protecting.Unprotect(CurrentUser?.DeliveryAddress) ?? string.Empty);
			CurrentUser.AboutMe = WebUtility.HtmlDecode(protecting.Unprotect(CurrentUser?.AboutMe) ?? string.Empty);
			CurrentUser.PhotoPath = HtmlEncoder.Default.Encode(protecting.Unprotect(CurrentUser.PhotoPath) ?? string.Empty);

			var sessionId = httpContext.Session.Id;
			_logger.LogInformation($"Session ID: {sessionId}");

			httpContext.Session.GetString("UserId");
			httpContext.Session.GetString("UserName");
			httpContext.Session.GetString("KeepSessionAlive");

            var timeSinceLastPasswordChange = DateTime.UtcNow - CurrentUser.PasswordChangedDate;

            if (timeSinceLastPasswordChange > TimeSpan.FromMinutes(60) && User.Identity.IsAuthenticated)
            {
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
			return "/images/default-profile.jpg";
		}
	}
}
