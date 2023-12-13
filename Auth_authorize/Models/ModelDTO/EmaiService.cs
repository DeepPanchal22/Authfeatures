namespace Auth_authorize.Models.ModelDTO
{
    public class EmaiService
    {
        public string To { get; set; }
        public string Subject { get; set; }
        public string Content { get; set; }
        public EmaiService(string to,string subject, string content)
        {
                To = to; Subject = subject; Content = content;
        }
    }
}
