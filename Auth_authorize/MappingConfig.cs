using Auth_authorize.Models;
using Auth_authorize.Models.ModelDTO;
using AutoMapper;

namespace Auth_authorize
{
    public class MappingConfig: Profile
    {
        public MappingConfig()
        {
                CreateMap<Users,AuthenticateDto>().ReverseMap();
                CreateMap<Users, SignupDto>().ReverseMap();
        }
    }
}
