namespace Auth_authorize.Models.ModelDTO
{
    public class AuthenticateDto
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string? Token { get; set; }
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime RefreshtokenExpirytime { get; set; }
    }
}
