using CloudinaryDotNet;
using CloudinaryDotNet.Actions;
using Microsoft.AspNetCore.Http;

namespace OpenTodo.Shared.Utils;

public class CloudinaryUploader
{
    private readonly Cloudinary _cloudinary;

    public CloudinaryUploader()
    {
        var account = new Account(
            Environment.GetEnvironmentVariable("CLOUDINARY_CLOUD_NAME"),
            Environment.GetEnvironmentVariable("CLOUDINARY_API_KEY"),
            Environment.GetEnvironmentVariable("CLOUDINARY_API_SECRET")
        );
        _cloudinary = new Cloudinary(account)
        {
            Api = { Secure = true }
        };
    }

    public async Task<string?> UploadImage(IFormFile file)
    {
        var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif", ".webp" };
        if (!allowedExtensions.Contains(Path.GetExtension(file.FileName).ToLower()))
        {
            throw new InvalidOperationException("Invalid file type. Only images are allowed.");
        }

        var uploadParams = new ImageUploadParams
        {
            File = new FileDescription(file.FileName, file.OpenReadStream()),
            UseFilename = true,
            UniqueFilename = true,
            Overwrite = true
        };
        
        var uploadResult = await _cloudinary.UploadAsync(uploadParams);
        if (uploadResult.Error != null)
        {
            throw new InvalidOperationException($"Error uploading image: {uploadResult.Error.Message}");
        }
        
        return uploadResult.SecureUrl?.ToString();
    }
}