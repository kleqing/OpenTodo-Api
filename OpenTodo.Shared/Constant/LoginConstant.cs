namespace OpenTodo.Shared.Constant;

public class LoginConstant
{
    //* Error Messages
    public static string AddUserToGoogleFailed = "Failed to add Google login to user!";
    public static string ClaimsPrincipalNotNull = "Claims principal cannot be null";
    public static string ClaimsPrincipalEmailNotFound = "Email claim not found in claims principal";
    public static string UsernameExists = "Username already exists!";
    public static string AccountNotFound = "Account not found!";
    public static string InvalidPassword = "Invalid password!";
    public static string EmailNotConfirmed = "Email not confirmed!";
    public static string EmailAlreadyConfirmed = "Email already confirmed!";
    public static string PasswordResetTokenExists = "Password reset token already exists!";
    public static string PasswordResetFailed = "Failed to initiate password reset!";
    public static string PasswordResetTokenInvalid = "Failed to verify password reset token!";
    public static string RedisUserIdNotFound = "User ID not found in Redis!";
    public static string CreateAccountFailed = "Failed to create account!";
    public static string InvalidPasswordResetToken = "Invalid or expired password reset token!";
    public static string UpdatePasswordFailed = "Failed to update user password!";
    public static string ResetPasswordFailed = "Failed to reset password!";
    public static string InvalidRefreshToken = "Invalid refresh token";
    public static string RefreshTokenExpired = "Refresh token has expired!";
    public static string EmailExists = "Email already exists!";
    public static string InvalidToken = "Invalid token!";
    
    //* Success Messages
    public static string LoginSuccess = "Login successful!";
    public static string AccountCreated = "Account created successfully!";
    public static string SendEmailSuccess = "Send to user email successfully!";
    public static string PasswordResetSuccess = "Password reset successfully!";
    public static string ValidToken = "Valid token!";
    public static string LogoutSuccess = "Logout successful!";
}