using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;

        public AccountController(DataContext context, ITokenService tokenService)
        {
            _context = context;
            _tokenService = tokenService;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDTO>> Register(RegisterDTO registerDto) {
            if(await UserExists(registerDto.UserName))
                return BadRequest("User Name is Taken");

            using var hmac = new HMACSHA512();

            var user = new AppUser {
                UserName = registerDto.UserName.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key
            };

            _context.Add(user);
            await _context.SaveChangesAsync();

            return new UserDTO 
            {
                UserName = user.UserName,
                Token = _tokenService.CreatToken(user)
            };
        }

        private async Task<bool> UserExists(string userName) {
            return await _context.Users.AnyAsync(x => x.UserName == userName.ToLower());
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDTO>> Login(LoginDTO loginDto) {
            var user = await _context.Users.Where(x => x.UserName == loginDto.UserName!.ToLower()).FirstOrDefaultAsync();

            if(user == null) {
                return Unauthorized("Invalid User Name");
            }

            using var hmac = new HMACSHA512(user.PasswordSalt);

            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password!));

            for (int i = 0; i < computedHash.Length; i++)
            {
                if(computedHash[i] != user.PasswordHash[i])
                    return Unauthorized("Invalid Password");
            }
            
            return new UserDTO 
            {
                UserName = user.UserName,
                Token = _tokenService.CreatToken(user)
            };
        }
    }
}