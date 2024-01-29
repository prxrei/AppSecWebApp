using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using AppSecWebApp.Model;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;

namespace AppSecWebApp.Pages
{
    [Authorize]
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public IndexModel(ILogger<IndexModel> logger, UserManager<ApplicationUser> userManager, IHttpContextAccessor httpContextAccessor)
        {
            _logger = logger;
            _userManager = userManager;
            _httpContextAccessor = httpContextAccessor;
        }

        public ApplicationUser CurrentUser { get; set; }

        public async Task OnGetAsync()
        {
            var dataProtectionProvider = DataProtectionProvider.Create("Encrypt");
            var protecting = dataProtectionProvider.CreateProtector("Key");
            CurrentUser = await _userManager.GetUserAsync(User);

            if (CurrentUser == null)
            {
                _logger.LogWarning("User is null in OnGetAsync.");
                return;
            }

            CurrentUser.FullName = protecting.Unprotect(CurrentUser.FullName) ?? string.Empty;

            // Log the session ID
            var sessionId = HttpContext.Session.Id;
            _logger.LogInformation($"Session ID: {sessionId}");

            // Reset the session timeout by updating session variables
            HttpContext.Session.SetString("UserId", CurrentUser.Id);
            HttpContext.Session.SetString("UserName", CurrentUser.UserName);
            HttpContext.Session.SetString("KeepSessionAlive", "true");
        }
    }
}
