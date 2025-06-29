using System.ComponentModel.DataAnnotations;

namespace LearningJwt.Domain.Models
{
    public class Login
    {
        [Required]
        public string Username { get; set; }
        public string Password { get; set; }
    }
}