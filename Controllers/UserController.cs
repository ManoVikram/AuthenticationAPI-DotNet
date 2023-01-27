using System.Text;
using System.Text.RegularExpressions;
using AuthenticationAPI.Context;
using AuthenticationAPI.Helpers;
using AuthenticationAPI.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationAPI.Controllers
{
    [Route("/api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;

        public UserController(AppDbContext appDbContext)
        {
            _authContext = appDbContext;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();

            var user = await _authContext.Users.FirstOrDefaultAsync(x => x.Email == userObj.Email && x.Password == userObj.Password);

            if (user == null)
                return NotFound(new { Message = "User Not Found!" });

            return Ok(new { Message = "Login Success!" });
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();

            // Chech whether the Email already exists
            if (await CheckEmailExistAsync(userObj.Email))
                return BadRequest(new { Message = "Email already exist!" });

            // Check password strength
            var passwordStrength = CheckPasswordStrength(userObj.Password);

            if (!string.IsNullOrEmpty(passwordStrength))
                return BadRequest(new { Message = passwordStrength.ToString() });

            // Hashing the password
            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Token = "";

            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();

            return Ok(new { Message = "User Registered!" });
        }

        private async Task<bool> CheckEmailExistAsync(string email)
        {
            return await _authContext.Users.AnyAsync(x => x.Email == email);
        }

        private string CheckPasswordStrength(string password)
        {
            StringBuilder stringBuilder = new StringBuilder();

            if (password.Length < 8)
                stringBuilder.Append("Minimum password length is 8" + Environment.NewLine);

            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]") && Regex.IsMatch(password, "[0-9]")))
                stringBuilder.Append("Password sould be alphanumeric" + Environment.NewLine);

            if (!Regex.IsMatch(password, "[<,>,=,~,{,},%,#,^,\\,\\[,\\],?,:,;,|,.,_,+,-]"))
                stringBuilder.Append("Password should contain special characters" + Environment.NewLine);

            return stringBuilder.ToString();
        }
    }
}