using Auth_authorize.Models.ModelDTO;

namespace Auth_authorize.UtilityServices
{
    public interface IEmailServices
    {
        void SendEmail(EmaiService emailservice);
    }
}
