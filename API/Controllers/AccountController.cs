using System.Security.Cryptography;
using System.Threading.Tasks;
using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using System.Text;
using API.DTOs;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;

        public AccountController(DataContext context)
        {
            _context = context;
        }
        [HttpPost("register")]
        public async Task<ActionResult<AppUser>> Register(RegisterDto registerdto)
        {
            if(await UserExist(registerdto.UserName)) return BadRequest("UserName already Taken");
                using var hmac = new HMACSHA512();
                var user = new AppUser {
                    UserName = registerdto.UserName.ToLower(),
                    PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerdto.Password)),
                    PasswordSalt = hmac.Key
                };

                _context.Add(user);
                await _context.SaveChangesAsync();
                return user;
        }
        
        [HttpPost("login")]
        public async Task<ActionResult<AppUser>> Login(LoginDto loginDto)
        {
           var user = await _context.Users.SingleOrDefaultAsync(u=>u.UserName == loginDto.UserName);
           if(user == null){
               return Unauthorized("Invalid username");
           }
           var hmac = new HMACSHA512(user.PasswordSalt);
           var computeHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));
           for (int i = 0; i < computeHash.Length; i++)
           {
               if(computeHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid credentials");
               
           }
           return user;
        }
        private async Task<bool> UserExist(string username)
        {
           return await _context.Users.AnyAsync(a => a.UserName == username.ToLower());
        }


    }
}