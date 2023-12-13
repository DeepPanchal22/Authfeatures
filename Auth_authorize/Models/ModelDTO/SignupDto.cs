using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

namespace Auth_authorize.Models.ModelDTO
{
    public class SignupDto
    {
        [Required]
        public string Firstname { get; set; }
        [Required]
        public string lastname { get; set; }
        [Required]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
        
        public string? Token { get; set; }
        public string? Role { get; set; }
        [Required]
        public string Email { get; set; }
    }
}
