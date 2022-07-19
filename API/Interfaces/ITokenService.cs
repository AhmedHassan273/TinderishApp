using API.Entities;

namespace API.Interfaces
{
    public interface ITokenService
    {
        string CreatToken(AppUser user);
    }
}