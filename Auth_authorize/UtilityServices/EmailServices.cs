using Auth_authorize.Models.ModelDTO;
using MailKit.Net.Smtp;
using Microsoft.Extensions.Hosting;
using MimeKit;
using System.Runtime.Intrinsics.X86;

namespace Auth_authorize.UtilityServices
{
    public class EmailServices:IEmailServices
    {
        //to read configuration we can use Iconfig

        private readonly IConfiguration _configuration;
        public EmailServices(IConfiguration configuration) 
        {
            _configuration = configuration;
        }

        public void SendEmail(EmaiService emailservice)
        {
            var mailMessage = new MimeMessage();
            var from = _configuration["EmailSetting:From"];
            mailMessage.From.Add(new MailboxAddress(from, from));
            mailMessage.To.Add(new MailboxAddress(emailservice.To, emailservice.To));
            mailMessage.Subject = emailservice.Subject;
            mailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Html)
            {
                Text = string.Format(emailservice.Content)
            };
            using (var smtpClient = new SmtpClient())
            {
                try 
                {
                    smtpClient.Connect(_configuration["EmailSetting:SmtpServer"], 465, true);
                    smtpClient.Authenticate(_configuration["EmailSetting:From"], _configuration["EmailSetting:Password"]);
                    smtpClient.Send(mailMessage);
                    smtpClient.Disconnect(true);
                }
                catch (Exception ex)
                {
                    throw ex;
                }
                finally 
                {
                    smtpClient.Disconnect(true);
                    smtpClient.Dispose();
                }
            }
        }
    }
}
