namespace Auth_authorize.Models.ModelDTO
{
    public class ResetPasswordDTO
    {
        public string Email { get; set; }
        public string Emailtoken { get; set; }
        public string Password { get; set; }
        public string ConfirmPassword { get; set; }
    }
}
