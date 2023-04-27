namespace SSOAuthorizationServer.Shared
{
    public class SSOLoginRequest
    {
        public string? UserId { get; set; }
        public string? Password { get; set; }
        public string? RedirectUri { get; set; }
    }
    public class AuthorizationCodeRequest
    {
        public string UserId { get; set; }
        public string Password { get; set; }
    }
    public class AuthorizationCodeResponse
    {
        public string UserId { get; set; }
        public string? AuthorizationCode { get; set; }
    }

    public class AccessTokenRequest
    {
        public string UserId { get; set; }
        public string? AuthorizationCode { get; set; }
    }

    public class AccessTokenResponse
    {
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
    }
}