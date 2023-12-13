using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Auth_authorize.Models
{
    public class Users
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public string Firstname { get; set; }
        public string lastname { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Token { get; set; }
        public string Role { get; set; }
        public string Email { get; set; }
        public string? RefreshToken { get; set; }

        public DateTime RefreshtokenExpirytime { get; set; }

        public string? ResetPasswordToken { get; set; }

        public DateTime ResetPasswordExpiery { get; set; }
    }
}
