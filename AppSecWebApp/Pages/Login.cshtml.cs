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
	using System.Net.Http;
	using Microsoft.EntityFrameworkCore;
	using Microsoft.AspNetCore.Authorization;

	namespace AppSecWebApp.Pages
	{
		[AllowAnonymous]
		public class LoginModel : PageModel
		{
			[BindProperty]
			public Login LModel { get; set; }

			private readonly SignInManager<ApplicationUser> _signInManager;
			private readonly ILogger<LoginModel> _logger;
			private readonly IHttpContextAccessor _httpContextAccessor;
			private readonly GoogleV3Captcha _service;

			public LoginModel(SignInManager<ApplicationUser> signInManager, ILogger<LoginModel> logger, IHttpContextAccessor httpContextAccessor, GoogleV3Captcha service)
			{
				_signInManager = signInManager;
				_logger = logger;
				_httpContextAccessor = httpContextAccessor;
				_service = service;
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
					return;
				}
			}

			[ValidateAntiForgeryToken]
			public async Task<IActionResult> OnPostAsync()
			{
				var captchaResult = await _service.CheckToken(LModel.Token);
				if (!captchaResult)
				{
					return Page();
				}

				if (ModelState.IsValid)
				{
					var identityResult = await _signInManager.PasswordSignInAsync(LModel.Email, LModel.Password, LModel.RememberMe, lockoutOnFailure: true);
					if (identityResult.Succeeded)
					{
						var user = await _signInManager.UserManager.FindByEmailAsync(LModel.Email);
						var httpContext = _httpContextAccessor.HttpContext;

						if (user != null)
						{
							if (httpContext.Session.GetString("UserId") == null)
							{
								httpContext.Session.SetString("LoginSs", LModel.Email.Trim());
								var sessionId = httpContext.Session.Id;
								_logger.LogInformation($"Session ID: {sessionId}");

								string authToken = Guid.NewGuid().ToString();
								_logger.LogInformation($"authtoken: {authToken}");

								httpContext.Session.SetString("AuthToken", authToken);
								_logger.LogInformation($"authtokenset: {httpContext.Session.GetString("AuthToken")}");

								httpContext.Response.Cookies.Append("AuthTokenCookie", authToken, new CookieOptions
								{
									Expires = DateTime.Now.AddHours(1),
									HttpOnly = true,
									SameSite = SameSiteMode.Strict
								});
								_logger.LogInformation($"authtokensetcookie: {httpContext.Response.Cookies}");

								string sessionIdentifier = Guid.NewGuid().ToString();

								httpContext.Session.SetString("SessionIdentifier", sessionIdentifier);

								httpContext.Response.Cookies.Append("SessionIdentifierCookie", sessionIdentifier, new CookieOptions
								{
									Expires = DateTime.Now.AddHours(1),
									HttpOnly = true,
									SameSite = SameSiteMode.Strict,
								});

								user.LastLogin = DateTime.UtcNow;

								await _signInManager.UserManager.UpdateAsync(user);

								httpContext.Session.SetString("UserId", user.Id);
								httpContext.Session.SetString("UserName", user.UserName);
								httpContext.Session.SetString("KeepSessionAlive", "true");

								_logger.LogInformation($"UserId: {httpContext.Session.GetString("UserId")}");
								_logger.LogInformation($"UserName: {httpContext.Session.GetString("UserName")}");

								var roles = await _signInManager.UserManager.GetRolesAsync(user);

								var claims = new List<Claim>
								{
									new Claim(ClaimTypes.Name, user.Email),
									new Claim(ClaimTypes.Email, user.Email),
								};

								claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

								return RedirectToPage("/Index");
							}
						}
					}
					else if (identityResult.IsLockedOut)
					{
						_logger.LogInformation("Account locked out");
						ModelState.AddModelError("", "Account locked out due to multiple failed login attempts. Please try again later.");
						ViewData["ErrorMessage"] = "Login failed. Account is Locked Out, Please try again later.";
					}
					else
					{
						_logger.LogInformation("Failed login attempt");
						ModelState.AddModelError("", "Username or Password incorrect");
						ViewData["ErrorMessage"] = "Login failed.";
					}
				}

				return Page();
			}

		}
	}
