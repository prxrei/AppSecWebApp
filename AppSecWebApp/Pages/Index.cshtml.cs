using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using AppSecWebApp.Model;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using System.Security.Cryptography;
using System.Net;

namespace AppSecWebApp.Pages
{
    [Authorize]
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private readonly UserManager<ApplicationUser> _userManager;

        public IndexModel(ILogger<IndexModel> logger, UserManager<ApplicationUser> userManager)
        {
            _logger = logger;
            _userManager = userManager;
        }

        public ApplicationUser CurrentUser { get; set; }

        public async Task OnGetAsync()
        {
            var dataProtectionProvider = DataProtectionProvider.Create("Encrypt");
            var _dataProtector = dataProtectionProvider.CreateProtector("Key");
            CurrentUser = await _userManager.GetUserAsync(User);

            if (CurrentUser == null)
            {
            _logger.LogWarning("User is null in OnGetAsync.");
                return;
            }

            // Log encrypted values (for debugging purposes)
            _logger.LogInformation($"Encrypted FullName: {_dataProtector.Protect(CurrentUser.FullName)}");
            CurrentUser.FullName = _dataProtector.Unprotect(CurrentUser.FullName) ?? string.Empty;
            _logger.LogInformation($"Decrypted FullName: {CurrentUser.FullName}");

        }
    }
}
