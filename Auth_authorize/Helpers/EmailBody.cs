namespace Auth_authorize.Helpers
{
    public static class EmailBody
    {
        public static string EmailStringBody(string Email,string EmailToken) 
        {
            return $@"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Email Confirmation</title>
        </head>
        <body>
            <h2>Email Confirmation</h2>
            <p>Dear user,</p>
            <p>Please confirm your email by clicking the link below:</p>
            <p>Email: {Email}</p>
            <p>Email Token: {EmailToken}</p>
            <a href='http://localhost:4200/reset?email={Email}&token={EmailToken}'>Confirm Email</a>
            <p>Thank you!</p>
        </body>
        </html>";
        }
    }
}
