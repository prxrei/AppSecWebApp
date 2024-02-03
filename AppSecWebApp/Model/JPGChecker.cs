using System.ComponentModel.DataAnnotations;


public class JPGChecker : ValidationAttribute
{
    private readonly string[] _extensions = {".jpg"};
    protected override ValidationResult IsValid(object test, ValidationContext validationContext)
    {
        if (test == null)
            return ValidationResult.Success;

        var imagefile = test as IFormFile;

        if (imagefile != null)
        {
            var extension = Path.GetExtension(imagefile.FileName);

            if (!_extensions.Contains(extension.ToLower()))
            {
                return new ValidationResult(ErrorMsg());
            }
        }
        return ValidationResult.Success;
    }

    public string ErrorMsg()
    {
        return "Only .JPG files are allowed.";
    }
}
