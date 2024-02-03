using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using AppSecWebApp.Model;
using AppSecWebApp.ViewModels;
using Microsoft.AspNetCore.Identity;

namespace AppSecWebApp.Pages
{
	[Authorize]
	public class ChangeThePwdModel : PageModel
	{
		private readonly ILogger<ChangeThePwdModel> _logger;
		private readonly UserManager<ApplicationUser> _userManager;

		public ChangeThePwdModel(ILogger<ChangeThePwdModel> logger, UserManager<ApplicationUser> userManager)
		{
			_logger = logger;
			_userManager = userManager;
		}

		[BindProperty]
		public ChangePwd ChangePwd { get; set; }

		public DateTime PasswordChangedDate { get; set; }

		public async Task<IActionResult> OnPostAsync()
		{
			if (ModelState.IsValid)
			{
				var user = await _userManager.GetUserAsync(User);

				if (user != null)
				{
					var checkCurrentPassword = await _userManager.CheckPasswordAsync(user, ChangePwd.CurrentPassword);

					if (!checkCurrentPassword)
					{
						ModelState.AddModelError("ChangePwd.CurrentPassword", "Current password is incorrect");
						return Page();
					}

					if (MyPwdHistory(user, ChangePwd.NewPassword))
					{
						ModelState.AddModelError("ChangePwd.NewPassword", "You cannot reuse one of your last two passwords.");
						return Page();
					}

					var timeSinceLastPasswordChange = DateTime.UtcNow - user.PasswordChangedDate;

					if (timeSinceLastPasswordChange < TimeSpan.FromSeconds(60) && timeSinceLastPasswordChange != null)
					{
						ModelState.AddModelError("ChangePwd.NewPassword", "You cannot change your password within 1 minute of the last change.");
						return Page();
					}

					var changePasswordResult = await _userManager.ChangePasswordAsync(user, ChangePwd.CurrentPassword, ChangePwd.NewPassword);

					if (changePasswordResult.Succeeded)
					{
						user.PasswordChangedDate = DateTime.UtcNow;

						UpdatePwdHistory(user, ChangePwd.NewPassword);

						await _userManager.UpdateAsync(user);
						await _userManager.UpdateSecurityStampAsync(user); 

						_logger.LogInformation("Password changed successfully.");
						return RedirectToPage("/Index");
					}
					else
					{
						foreach (var error in changePasswordResult.Errors)
						{
							ModelState.AddModelError(string.Empty, error.Description);
						}
						return Page();
					}
				}
			}
			return Page();
		}

		private bool MyPwdHistory(ApplicationUser user, string newPassword)
		{
			var pwdHashes = user.PasswordHashHistory?.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);

			if (pwdHashes == null)
			{
				return false;
			}

			var MyPwdHistory = pwdHashes.Any(hash => _userManager.PasswordHasher.VerifyHashedPassword(user, hash, newPassword) != PasswordVerificationResult.Failed);

			return MyPwdHistory;
		}

		private void UpdatePwdHistory(ApplicationUser user, string newPassword)
		{
			const int maxHistoryCount = 2;

			var pwdHistory = user.PasswordHashHistory?.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries).ToList() ?? new List<string>();

			pwdHistory.Insert(0, HashPwd(user, newPassword));

			pwdHistory = pwdHistory.Take(maxHistoryCount).ToList();

			user.PasswordHashHistory = string.Join(';', pwdHistory);
		}

		private string HashPwd(ApplicationUser user, string password)
		{
			return _userManager.PasswordHasher.HashPassword(user, password);
		}

	}
}
