using API.Entities;

namespace API.Interfaces
{
    public interface ITokenService
    {
         string CreateToke(AppUser user);
    }
}