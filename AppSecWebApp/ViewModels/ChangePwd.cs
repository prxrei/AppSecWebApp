using System.ComponentModel.DataAnnotations;

namespace AppSecWebApp.ViewModels
{
    public class ChangePwd
    {
        [Required(ErrorMessage = "Current Password is required")]
        [DataType(DataType.Password)]
        public string CurrentPassword { get; set; }

        [Required(ErrorMessage = "New Password is required")]
        [DataType(DataType.Password)]
        public string NewPassword { get; set; }

        [Required(ErrorMessage = "Confirm New Password is required")]
        [DataType(DataType.Password)]
        public string ConfirmNewPassword { get; set; }
    }
}
