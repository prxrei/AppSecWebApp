using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.Security.Claims;
using AppSecWebApp.ViewModels;
using AppSecWebApp.Model;
using IdentityUser = Microsoft.AspNetCore.Identity.IdentityUser;
using Microsoft.AspNetCore.Http;

namespace AppSecWebApp.Pages
{
	public class LoginModel : PageModel
	{
		[BindProperty]
		public Login LModel { get; set; }

		public string LoginErrorMessage { get; set; }

		private readonly SignInManager<ApplicationUser> signInManager;
		private readonly ILogger<LoginModel> _logger;
		private readonly IHttpContextAccessor _httpContextAccessor;

		public LoginModel(SignInManager<ApplicationUser> signInManager, ILogger<LoginModel> logger, IHttpContextAccessor httpContextAccessor)
		{
			this.signInManager = signInManager;
			_logger = logger;
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
				var identityResult = await signInManager.PasswordSignInAsync(LModel.Email, LModel.Password, LModel.RememberMe, false);
				if (identityResult.Succeeded)
				{
					var user = await signInManager.UserManager.FindByEmailAsync(LModel.Email);
					var httpContext = _httpContextAccessor.HttpContext;

					if (user != null)
					{
						// Set normal Session variable
						httpContext.Session.SetString("LoginSs", LModel.Email.Trim());
						var sessionId = httpContext.Session.Id;
						_logger.LogInformation($"Session ID: {sessionId}");

						// Generate a GUID for AuthToken
						string authToken = Guid.NewGuid().ToString();
						_logger.LogInformation($"authtoken: {authToken}");

						// Save AuthToken in Session
						httpContext.Session.SetString("AuthToken", authToken);
						_logger.LogInformation($"authtokenset: {httpContext.Session.GetString("AuthToken")}");

						// Save AuthToken in a cookie
						httpContext.Response.Cookies.Append("AuthToken", authToken, new CookieOptions
						{
							Expires = DateTime.Now.AddHours(1), // Set expiration time as needed
							HttpOnly = true, // Helps prevent XSS attacks
							SameSite = SameSiteMode.Strict // Adjust as needed
						});
						_logger.LogInformation($"authtokensetcookie: {httpContext.Response.Cookies}");

						// Generate a unique session identifier (you may use a GUID, for example)
						string sessionIdentifier = Guid.NewGuid().ToString();

						// Store the session identifier in the user's session
						httpContext.Session.SetString("SessionIdentifier", sessionIdentifier);

						// Store the session identifier in a secure cookie
						httpContext.Response.Cookies.Append("SessionIdentifierCookie", sessionIdentifier, new CookieOptions
						{
							HttpOnly = true,
							SameSite = SameSiteMode.Strict,
							// Set other cookie options as needed
						});

						// Update UniqueIdentifier in the user entity
						user.UniqueIdentifier = Guid.NewGuid().ToString();
						await signInManager.UserManager.UpdateAsync(user);

						// Store user-related data in session
						httpContext.Session.SetString("UserId", user.Id);
						httpContext.Session.SetString("UserName", user.UserName);
						httpContext.Session.SetString("KeepSessionAlive", "true");
						// Add other user-related data to session as needed

						_logger.LogInformation($"UserId: {httpContext.Session.GetString("UserId")}");
						_logger.LogInformation($"UserName: {httpContext.Session.GetString("UserName")}");

						// Redirect to the absolute path of the Index page
						return RedirectToPage("/Index");
					}
				}
				ModelState.AddModelError("", "Username or Password incorrect");
			}
			return Page();
		}
	}
}
