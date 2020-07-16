using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace UserManagement.API.Models
{
    public class LoginResponseModel
    {
        public string token { get; set; }
        public string UserName { get; set; }
        public bool status { get; set; }
        public string Massage { get; set; }
    }
    
}