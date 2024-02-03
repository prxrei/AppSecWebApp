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

					if (IsPasswordInHistory(user, ChangePwd.NewPassword))
					{
						ModelState.AddModelError("ChangePwd.NewPassword", "You cannot reuse one of your last two passwords.");
						return Page();
					}

					var timeSinceLastPasswordChange = DateTime.UtcNow - user.PasswordChangedDate;

					// Check if the user can change the password based on the minimum password age
					if (timeSinceLastPasswordChange < TimeSpan.FromSeconds(60) && timeSinceLastPasswordChange != null)
					{
						ModelState.AddModelError("ChangePwd.NewPassword", "You cannot change your password within 1 minute of the last change.");
						return Page();
					}

					var changePasswordResult = await _userManager.ChangePasswordAsync(user, ChangePwd.CurrentPassword, ChangePwd.NewPassword);

					if (changePasswordResult.Succeeded)
					{
						// Update the last password change timestamp
						user.PasswordChangedDate = DateTime.UtcNow;

						// Update the password history
						UpdatePasswordHistory(user, ChangePwd.NewPassword);

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
			// If ModelState is not valid or if there's an error, redisplay the form
			return Page();
		}

		private bool IsPasswordInHistory(ApplicationUser user, string newPassword)
		{
			// Split the stored password history into individual hashes
			var passwordHashes = user.PasswordHashHistory?.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);

			if (passwordHashes == null)
			{
				return false;
			}

			// Hash the new password for comparison
			var hashedPassword = _userManager.PasswordHasher.HashPassword(user, newPassword);

			// Check if the new hashed password is present in the stored hashes in the database(VerifyHashedPassword also checks through salting)
			var isPasswordInHistory = passwordHashes.Any(hash => _userManager.PasswordHasher.VerifyHashedPassword(user, hash, newPassword) != PasswordVerificationResult.Failed);

			// Log the result for debugging
			_logger.LogInformation($"IsPasswordInHistory: {isPasswordInHistory}");

			return isPasswordInHistory;
		}

		private void UpdatePasswordHistory(ApplicationUser user, string newPassword)
		{
			const int maxHistoryCount = 2;

			// Get the current password history
			var passwordHistory = user.PasswordHashHistory?.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries).ToList() ?? new List<string>();

			// Add the new password hash to the history without hashing again
			passwordHistory.Insert(0, HashPassword(user, newPassword));

			// Trim the history to the maximum allowed count
			passwordHistory = passwordHistory.Take(maxHistoryCount).ToList();

			// Update the PasswordHashHistory property
			user.PasswordHashHistory = string.Join(';', passwordHistory);
		}

		private string HashPassword(ApplicationUser user, string password)
		{
			return _userManager.PasswordHasher.HashPassword(user, password);
		}

	}
}
