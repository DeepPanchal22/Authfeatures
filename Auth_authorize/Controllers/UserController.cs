using Auth_authorize.Context;
using Auth_authorize.Helpers;
using Auth_authorize.Models;
using Auth_authorize.Models.ModelDTO;
using Auth_authorize.UtilityServices;
using AutoMapper;
using Azure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using NETCore.MailKit.Core;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Auth_authorize.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IMapper _mapper;
        private readonly IConfiguration _configuration;
        private readonly IEmailServices _emailService;

        public UserController(AppDbContext context,IMapper mapper,IConfiguration configuration,IEmailServices emailService)
        {
            _context = context;
            _mapper = mapper;
            _configuration = configuration;
            _emailService = emailService;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> authenticate([FromBody] AuthenticateDto authenticate)
        {
            if (authenticate == null) { return NoContent(); }

            authenticate.Password = PasswordHasher.Encrypt(authenticate.Password);
            var user = await _context.User.Where(u => u.Username == authenticate.Username && u.Password == authenticate.Password).FirstOrDefaultAsync();

          
            if (user == null)
            {
                return NotFound(new { Message = "User not found!!!!" });
            }
            else
            {
                authenticate.Token = CreateToken(user);

                var newaccesstoken = authenticate.Token;
                var refreshtoken = CreateRefreshToken();
                authenticate.RefreshToken = refreshtoken;
                authenticate.RefreshtokenExpirytime = DateTime.UtcNow.AddDays(5);
                user.RefreshtokenExpirytime = authenticate.RefreshtokenExpirytime;
                user.RefreshToken = refreshtoken;

                _context.Entry(user).State = EntityState.Modified;
                await _context.SaveChangesAsync();
                return Ok(new TokenapiDTO()
                { 
                    AccessToken=newaccesstoken,
                    RefreshToken=refreshtoken
                });
            }
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] SignupDto signup) 
        {
            if (signup == null) 
            {
                return NoContent();
            }
            //check username

            if (await checkusername(signup.Username)) 
            {
             return BadRequest(new { Message = "Username already exist"});
            }


            //check email

            if (await checkEmail(signup.Email))
            {
                return BadRequest(new { Message = "Email already exist" });
            }


            //check password
            if (!IsStrongPassword(signup.Password)) 
            {
                return BadRequest(new {Message = "password is not strong"});
            }
            signup.Token = "string";
            signup.Password = PasswordHasher.Encrypt(signup.Password);
            Users user = _mapper.Map<Users>(signup);
            await _context.AddAsync(user);
            _context.SaveChanges();
            return CreatedAtAction(nameof(Register), signup);

        }


        [Authorize]
        [HttpGet("GetAllUsers")]
        public async Task<ActionResult<Users>> GetallUser() 
        {
            return Ok(await _context.User.ToListAsync());
        }


        [HttpPost("Refresh")]
        public async Task<IActionResult> refresh([FromBody] TokenapiDTO tokenDto) 
        {
            if (tokenDto is null)
                return BadRequest("invalid client request");
            string accesstoken = tokenDto.AccessToken;
            string refreshtoken = tokenDto.RefreshToken;

            var principle = GetprincipleFromExpiredToken(accesstoken);
            var username = principle.Identity.Name;
            var user = await _context.User.FirstOrDefaultAsync(x => x.Username == username);
            if (user is null || user.RefreshToken != refreshtoken || user.RefreshtokenExpirytime <= DateTime.Now)
                return BadRequest("invalid request");

            var newaccesstoken = CreateToken(user);
            var newrefreshtoken = CreateRefreshToken();
            user.RefreshToken = newrefreshtoken;
            await _context.SaveChangesAsync();
            return Ok(new TokenapiDTO() 
            {
                AccessToken = newaccesstoken,
                RefreshToken = newrefreshtoken,
            });
        }

        [HttpPost("send-reset-email/{email}")]
        public async Task<IActionResult> SendEmail(string email) 
        {
            var user = await _context.User.FirstOrDefaultAsync(a=>a.Email == email);
            if (user is null)
                return NotFound(new
                {
                    StatusCode = 404,
                    Message = "Email Not Found"
                });
            var tokenbytes = RandomNumberGenerator.GetBytes(64);
            var emailToken = Convert.ToBase64String(tokenbytes);
            user.ResetPasswordToken = emailToken;
            user.ResetPasswordExpiery = DateTime.Now.AddMinutes(15);
            string from = _configuration["EmailSetting:From"];
            var emailmodel = new EmaiService(email,"Reset Password!!",EmailBody.EmailStringBody(email,emailToken));
            _emailService.SendEmail(emailmodel);
            _context.Entry(user).State = EntityState.Modified;
            await _context.SaveChangesAsync();

            return Ok
                (
                    new 
                    {
                    StatusCode= 200,
                    Message= "Email sent successfully"
                    }
                );

        }

        //reset password

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordDTO resetpassword)
        {
            //var newtoken = resetpassword.Emailtoken.Replace("", "+");
            var user = await _context.User.AsNoTracking().FirstOrDefaultAsync(a => a.Email == resetpassword.Email);
            //asnotracking returns new query which arent saved in cache so it does not have tracking 
            //thi query will read database origin but won't saved in context.
            if (user is null)
                return NotFound(new
                {
                    StatusCode = 404,
                    Message = "Email Not Found"
                });

            var tokenCode = user.ResetPasswordToken;
            DateTime emailtokenExpiry = user.ResetPasswordExpiery;
            if (tokenCode != resetpassword.Emailtoken || emailtokenExpiry < DateTime.Now)
            {
                return BadRequest(new
                {
                    StatusCode=400,
                    Message="Invalid reset Link"
                });
            }
            user.Password = PasswordHasher.Encrypt(resetpassword.Password);
            _context.Entry(user).State= EntityState.Modified;
            await _context.SaveChangesAsync();
            return Ok(new 
            {
                StatusCode = 200,
                Message="PAssword reseted successfully"
            });

        }
        private Task<bool> checkusername(string username) => _context.User.AnyAsync(x => x.Username == username);

        private Task<bool> checkEmail(string email) => _context.User.AnyAsync(x => x.Email == email);
        private bool IsStrongPassword(string password)
        {
            // Check if password meets criteria (alphanumeric and length > 8)
            return !string.IsNullOrEmpty(password) && password.Length > 8 && ContainsAlphabetsAndNumbers(password);
        }

        private bool ContainsAlphabetsAndNumbers(string input)
        {
            return input.Any(char.IsLetter) && input.Any(char.IsDigit);
        }

        private string CreateToken(Users user) 
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("veryverysecret....");
            var identity = new ClaimsIdentity(new Claim[] 
            {
                new Claim(ClaimTypes.Role,user.Role),
                new Claim(ClaimTypes.Name,user.Username),

            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key),SecurityAlgorithms.HmacSha256);

            var tokenDescripter = new SecurityTokenDescriptor
            {
                Subject = identity,
                //Expires = DateTime.Now.AddMinutes(5),
                Expires = DateTime.Now.AddSeconds(10),
                SigningCredentials = credentials,
            };


            var token = jwtTokenHandler.CreateToken(tokenDescripter);
            return jwtTokenHandler.WriteToken(token);
        }


        private ClaimsPrincipal GetprincipleFromExpiredToken(string token) 
        {
            var key = Encoding.ASCII.GetBytes("veryverysecret....");
            var tokenvalidationparameter = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false,
            };
            var tokenhandler =new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principle = tokenhandler.ValidateToken(token, tokenvalidationparameter, out securityToken);

            var jwtsecuritytoken = securityToken as JwtSecurityToken;
            if (jwtsecuritytoken == null || !jwtsecuritytoken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("token is Invalid");
            return principle;
        }

        private string CreateRefreshToken() 
        {
            var tokenbytes = RandomNumberGenerator.GetBytes(64);

            var refreshtoken = Convert.ToBase64String(tokenbytes);

            var tokenInUser =  _context.User.Any(a => a.RefreshToken == refreshtoken);

            if (tokenInUser) 
            {
                return CreateRefreshToken();
            }

            return refreshtoken;
        }

    }
}
