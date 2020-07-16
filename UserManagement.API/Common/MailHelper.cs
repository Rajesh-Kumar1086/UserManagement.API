using Microsoft.SqlServer.Server;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Web;

namespace UserManagement.API.Common
{
    public static class MailHelper
    {
        public static void SendEmail(MailServer mailServer)
        {
            using (MailMessage mail = new MailMessage())
            {
                mail.From = new MailAddress(mailServer.emailFromAddress);
                mail.To.Add(mailServer.emailToAddress);
                mail.Subject = mailServer.subject;
                mail.Body = mailServer.body;
                mail.IsBodyHtml = true;
                //mail.Attachments.Add(new Attachment("D:\\TestFile.txt"));//--Uncomment this to send any attachment  
                using (SmtpClient smtp = new SmtpClient(mailServer.smtpAddress, mailServer.portNumber))
                {
                    smtp.UseDefaultCredentials = true;
                    smtp.EnableSsl = mailServer.enableSSL;
                    smtp.Credentials = new NetworkCredential(mailServer.emailFromAddress.Trim(), mailServer.password.Trim());
                    smtp.Send(mail);
                }
            }
        }

    }
    public class MailServer
    {
        public string smtpAddress { get; set; }
        public int portNumber { get; set; }
        public bool enableSSL { get; set; }
        public string emailFromAddress { get; set; }
        public string password { get; set; }
        public string emailToAddress { get; set; }
        public string subject { get; set; }
        public string body { get; set; }
    }


}