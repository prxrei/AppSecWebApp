using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AppSecWebApp.Pages
{
    [Authorize]
    public class AccessDeniedModel : PageModel
    {
        public void OnGet()
        {
        }
    }
}
