using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Web;

namespace UserManagement.API.Services
{
    public class EmailService
    {

        public bool SendMail(MailMessage mailMessage)
        {
            bool mailsent = true;
            using (SmtpClient smtpClient = new SmtpClient())
            {
                try
                {
                    smtpClient.Host = "smtp.gmail.com";
                    smtpClient.EnableSsl = true;
                    smtpClient.UseDefaultCredentials = true;
                    smtpClient.Credentials = new NetworkCredential("espranzainova@gmail.com", "espranza554");
                    smtpClient.Port = 587;
                    smtpClient.Send(mailMessage);
                }
                catch (Exception ex)
                {
                    mailsent = false;
                    throw ex;
                }
                return mailsent;
            }
        }
    }
}