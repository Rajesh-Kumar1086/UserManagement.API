using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Net.Http;
using System.Net.Mail;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Configuration;
using System.Web.Http;
using System.Web.Http.ModelBinding;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using UserManagement.API.Common;
using UserManagement.API.Models;
using UserManagement.API.Providers;
using UserManagement.API.Results;
using UserManagement.API.Services;

namespace UserManagement.API.Controllers
{
    [Authorize]
    [RoutePrefix("api/Account")]
    public class AccountController : ApiController
    {
        private const string LocalLoginProvider = "Local";
        private ApplicationUserManager _userManager;
        private ApplicationRoleManager _roleManager;
        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager,
            ISecureDataFormat<AuthenticationTicket> accessTokenFormat, ApplicationRoleManager roleManager)
        {
            UserManager = userManager;
            AccessTokenFormat = accessTokenFormat;
            RoleManager = roleManager;
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? Request.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }
        public ApplicationRoleManager RoleManager
        {
            get
            {
                return _roleManager ?? Request.GetOwinContext().GetUserManager<ApplicationRoleManager>();
            }
            private set
            {
                _roleManager = value;
            }
        }

        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; private set; }

        // GET api/Account/UserInfo
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("UserInfo")]
        public UserInfoViewModel GetUserInfo()
        {
            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            return new UserInfoViewModel
            {
                Email = User.Identity.GetUserName(),
                HasRegistered = externalLogin == null,
                LoginProvider = externalLogin != null ? externalLogin.LoginProvider : null
            };
        }

        // POST api/Account/Logout
        [Route("Logout")]
        public IHttpActionResult Logout()
        {
            Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            return Ok();
        }

        // GET api/Account/ManageInfo?returnUrl=%2F&generateState=true
        [Route("ManageInfo")]
        public async Task<ManageInfoViewModel> GetManageInfo(string returnUrl, bool generateState = false)
        {
            IdentityUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

            if (user == null)
            {
                return null;
            }

            List<UserLoginInfoViewModel> logins = new List<UserLoginInfoViewModel>();

            foreach (IdentityUserLogin linkedAccount in user.Logins)
            {
                logins.Add(new UserLoginInfoViewModel
                {
                    LoginProvider = linkedAccount.LoginProvider,
                    ProviderKey = linkedAccount.ProviderKey
                });
            }

            if (user.PasswordHash != null)
            {
                logins.Add(new UserLoginInfoViewModel
                {
                    LoginProvider = LocalLoginProvider,
                    ProviderKey = user.UserName,
                });
            }

            return new ManageInfoViewModel
            {
                LocalLoginProvider = LocalLoginProvider,
                Email = user.UserName,
                Logins = logins,
                ExternalLoginProviders = GetExternalLogins(returnUrl, generateState)
            };
        }

        // POST api/Account/ChangePassword
        [Route("ChangePassword")]
        public async Task<IHttpActionResult> ChangePassword(ChangePasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await UserManager.ChangePasswordAsync(User.Identity.GetUserId(), model.OldPassword,
                model.NewPassword);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }




            // POST api/Account/SetPassword
            [Route("SetPassword")]
        public async Task<IHttpActionResult> SetPassword(SetPasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await UserManager.AddPasswordAsync(User.Identity.GetUserId(), model.NewPassword);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/AddExternalLogin
        [Route("AddExternalLogin")]
        public async Task<IHttpActionResult> AddExternalLogin(AddExternalLoginBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);

            AuthenticationTicket ticket = AccessTokenFormat.Unprotect(model.ExternalAccessToken);

            if (ticket == null || ticket.Identity == null || (ticket.Properties != null
                && ticket.Properties.ExpiresUtc.HasValue
                && ticket.Properties.ExpiresUtc.Value < DateTimeOffset.UtcNow))
            {
                return BadRequest("External login failure.");
            }

            ExternalLoginData externalData = ExternalLoginData.FromIdentity(ticket.Identity);

            if (externalData == null)
            {
                return BadRequest("The external login is already associated with an account.");
            }

            IdentityResult result = await UserManager.AddLoginAsync(User.Identity.GetUserId(),
                new UserLoginInfo(externalData.LoginProvider, externalData.ProviderKey));

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/RemoveLogin
        [Route("RemoveLogin")]
        public async Task<IHttpActionResult> RemoveLogin(RemoveLoginBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result;

            if (model.LoginProvider == LocalLoginProvider)
            {
                result = await UserManager.RemovePasswordAsync(User.Identity.GetUserId());
            }
            else
            {
                result = await UserManager.RemoveLoginAsync(User.Identity.GetUserId(),
                    new UserLoginInfo(model.LoginProvider, model.ProviderKey));
            }

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // GET api/Account/ExternalLogin
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalCookie)]
        [AllowAnonymous]
        [Route("ExternalLogin", Name = "ExternalLogin")]
        public async Task<IHttpActionResult> GetExternalLogin(string provider, string error = null)
        {
            if (error != null)
            {
                return Redirect(Url.Content("~/") + "#error=" + Uri.EscapeDataString(error));
            }

            if (!User.Identity.IsAuthenticated)
            {
                return new ChallengeResult(provider, this);
            }

            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            if (externalLogin == null)
            {
                return InternalServerError();
            }

            if (externalLogin.LoginProvider != provider)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                return new ChallengeResult(provider, this);
            }

            ApplicationUser user = await UserManager.FindAsync(new UserLoginInfo(externalLogin.LoginProvider,
                externalLogin.ProviderKey));

            bool hasRegistered = user != null;

            if (hasRegistered)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);

                ClaimsIdentity oAuthIdentity = await user.GenerateUserIdentityAsync(UserManager,
                   OAuthDefaults.AuthenticationType);
                ClaimsIdentity cookieIdentity = await user.GenerateUserIdentityAsync(UserManager,
                    CookieAuthenticationDefaults.AuthenticationType);

                AuthenticationProperties properties = ApplicationOAuthProvider.CreateProperties(user.UserName);
                Authentication.SignIn(properties, oAuthIdentity, cookieIdentity);
            }
            else
            {
                IEnumerable<Claim> claims = externalLogin.GetClaims();
                ClaimsIdentity identity = new ClaimsIdentity(claims, OAuthDefaults.AuthenticationType);
                Authentication.SignIn(identity);
            }

            return Ok();
        }

        // GET api/Account/ExternalLogins?returnUrl=%2F&generateState=true
        [AllowAnonymous]
        [Route("ExternalLogins")]
        public IEnumerable<ExternalLoginViewModel> GetExternalLogins(string returnUrl, bool generateState = false)
        {
            IEnumerable<AuthenticationDescription> descriptions = Authentication.GetExternalAuthenticationTypes();
            List<ExternalLoginViewModel> logins = new List<ExternalLoginViewModel>();

            string state;

            if (generateState)
            {
                const int strengthInBits = 256;
                state = RandomOAuthStateGenerator.Generate(strengthInBits);
            }
            else
            {
                state = null;
            }

            foreach (AuthenticationDescription description in descriptions)
            {
                ExternalLoginViewModel login = new ExternalLoginViewModel
                {
                    Name = description.Caption,
                    Url = Url.Route("ExternalLogin", new
                    {
                        provider = description.AuthenticationType,
                        response_type = "token",
                        client_id = Startup.PublicClientId,
                        redirect_uri = new Uri(Request.RequestUri, returnUrl).AbsoluteUri,
                        state = state
                    }),
                    State = state
                };
                logins.Add(login);
            }

            return logins;
        }

        // POST api/Account/Register
        [AllowAnonymous]
        [Route("Register")]
        public async Task<IHttpActionResult> Register(RegisterBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var user = new ApplicationUser() { UserName = model.Email, Email = model.Email };

            user.IsDeleted = false;
            user.IsActive = false;
            user.CreatedDate = DateTime.Now;
            user.ModifyDate = DateTime.Now;
            user.Activation = Guid.NewGuid();
            IdentityResult result = await UserManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                MailServer mailServer = new MailServer();
                mailServer.smtpAddress = ConfigurationManager.AppSettings["Host"];
                mailServer.portNumber = int.Parse(ConfigurationManager.AppSettings["Port"]);
                mailServer.enableSSL = bool.Parse(ConfigurationManager.AppSettings["SSL"]);
                mailServer.emailFromAddress = ConfigurationManager.AppSettings["FromEmail"];
                mailServer.password = ConfigurationManager.AppSettings["Password"];
                mailServer.emailToAddress = model.Email;
                var host = "localhost";
                var port = "44346";
                var varifyUrl = "https://" + host + ":" + port + "/api/Account/UserConfirm/" + user.Activation;
                mailServer.subject = "Your account is successfull created";
                mailServer.body = "<br/><br/>We are excited to tell you that your account is" +
                   " successfully created. Please click on the below link to verify your account" +
                      " <br/><br/><a href='" + varifyUrl + "'>" + varifyUrl + "</a> ";
                try
                {
                    MailHelper.SendEmail(mailServer);
                    //  return "Registration has been done,And Account activation link" + "has been sent your eamil id:" + model.Email;
                }
                catch (Exception ex)
                {
                    //result.Errors = ex.Message;
                }
            }
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }
            return Ok();
        }
        // POST api/Account/Login
        [AllowAnonymous]
        [Route("Login")]
        public LoginResponseModel Login(LoginRequestModel model)
        {
            if (ModelState.IsValid)
            {
                // IOwinContext owinContext = HttpContext.GetOwinContext();
                // IAuthenticationManager authenticationManager = owinContext.Authentication;
                var user = UserManager.Find(model.Email, model.Password);

                if (user != null)
                {
                    if (user.IsDeleted)
                    {
                        return new LoginResponseModel
                        {
                            Massage = "User already deleted",
                            status = false
                        };
                    }
                    if (!user.IsActive)
                    {
                        return new LoginResponseModel
                        {
                            Massage = "User not active, please confirm user by mail",
                            status = false
                        };

                    }

                    var identity = UserManager.CreateIdentity(user, DefaultAuthenticationTypes.ExternalBearer);
                    // Sign in cookie
                    var properties = new AuthenticationProperties(
                        new System.Collections.Generic.Dictionary<string, string>
                        {
                        { "userName", model.Email }
                        })
                    { IsPersistent = false /* model.Remember */ };
                    AuthenticationTicket ticket = new AuthenticationTicket(identity, properties);
                    var token = Startup.OAuthOptions.AccessTokenFormat.Protect(ticket);

                    return new LoginResponseModel
                    {
                        token = token,
                        UserName = model.Email,
                        status = true
                    };
                }
                else
                {
                    return new LoginResponseModel
                    {

                        Massage = "User not found",
                        status = false
                    };
                }


            }
            else
            {
                return new LoginResponseModel
                {
                    Massage = "Invalid user",
                    status = true
                };
            }


        }
        [AllowAnonymous]
        [Route("ForgotPassword")]
        public string ForgotPassword(string username)
        {
            string msg = "";
            if (username != null)
            {
                try
                {
                    var user = UserManager.FindByEmail(username);
                    if (user.IsActive)
                    {
                        string url = HttpContext.Current.Request.Url.AbsoluteUri;
                        int resetCode = new Random().Next();
                        StringBuilder builder = new StringBuilder();
                        MailMessage informMessage = new MailMessage();
                        var host = "localhost";
                        var port = "44346";
                        informMessage.From = new MailAddress(ConfigurationManager.AppSettings["FromEmail"]);
                        informMessage.To.Add(username);
                        var varifyUrl = "https://" + host + ":" + port + "/api/Account/SetPassword/";
                        informMessage.Subject = "Reset Password";
                        informMessage.Body = "<br/><br/>We are excited to tell you that your account is" +
                           " successfully created. Please click on the below link to verify your account" +
                              " <br/><br/><a href='" + varifyUrl + "'>" + varifyUrl + "</a> ";
                        // string body = string.Format("<br /><a target='_blank' href='{0}SetPassword?username={1}&key={2}' style='background-color:#ccc;padding:5px;text-decoration:none;cursor:pointer;border:1px solid #000;'>Reset Password</a>", "https://localhost:44315/Api/Account/", username, resetCode);
                        informMessage.IsBodyHtml = true;
                        EmailService emailService = new EmailService();
                        emailService.SendMail(informMessage);
                        msg = "Please check your mail";
                    }
                    else
                    {
                        msg = "User not activated";
                    }
                }
                catch (Exception ex)
                {

                    msg = ex.Message;
                }

            }
            return msg;

        }

        // POST api/Account/RegisterExternal
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("RegisterExternal")]
        public async Task<IHttpActionResult> RegisterExternal(RegisterExternalBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var info = await Authentication.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return InternalServerError();
            }

            var user = new ApplicationUser() { UserName = model.Email, Email = model.Email };

            IdentityResult result = await UserManager.CreateAsync(user);
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            result = await UserManager.AddLoginAsync(user.Id, info.Login);
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }
            return Ok();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && _userManager != null)
            {
                _userManager.Dispose();
                _userManager = null;
            }

            base.Dispose(disposing);
        }

        #region Helpers

        private IAuthenticationManager Authentication
        {
            get { return Request.GetOwinContext().Authentication; }
        }


        private IHttpActionResult GetErrorResult(IdentityResult result)
        {
            if (result == null)
            {
                return InternalServerError();
            }

            if (!result.Succeeded)
            {
                if (result.Errors != null)
                {
                    foreach (string error in result.Errors)
                    {
                        ModelState.AddModelError("", error);
                    }
                }

                if (ModelState.IsValid)
                {
                    // No ModelState errors are available to send, so just return an empty BadRequest.
                    return BadRequest();
                }

                return BadRequest(ModelState);
            }

            return null;
        }

        private class ExternalLoginData
        {
            public string LoginProvider { get; set; }
            public string ProviderKey { get; set; }
            public string UserName { get; set; }

            public IList<Claim> GetClaims()
            {
                IList<Claim> claims = new List<Claim>();
                claims.Add(new Claim(ClaimTypes.NameIdentifier, ProviderKey, null, LoginProvider));

                if (UserName != null)
                {
                    claims.Add(new Claim(ClaimTypes.Name, UserName, null, LoginProvider));
                }

                return claims;
            }

            public static ExternalLoginData FromIdentity(ClaimsIdentity identity)
            {
                if (identity == null)
                {
                    return null;
                }

                Claim providerKeyClaim = identity.FindFirst(ClaimTypes.NameIdentifier);

                if (providerKeyClaim == null || String.IsNullOrEmpty(providerKeyClaim.Issuer)
                    || String.IsNullOrEmpty(providerKeyClaim.Value))
                {
                    return null;
                }

                if (providerKeyClaim.Issuer == ClaimsIdentity.DefaultIssuer)
                {
                    return null;
                }

                return new ExternalLoginData
                {
                    LoginProvider = providerKeyClaim.Issuer,
                    ProviderKey = providerKeyClaim.Value,
                    UserName = identity.FindFirstValue(ClaimTypes.Name)
                };
            }
        }

        private static class RandomOAuthStateGenerator
        {
            private static RandomNumberGenerator _random = new RNGCryptoServiceProvider();

            public static string Generate(int strengthInBits)
            {
                const int bitsPerByte = 8;

                if (strengthInBits % bitsPerByte != 0)
                {
                    throw new ArgumentException("strengthInBits must be evenly divisible by 8.", "strengthInBits");
                }

                int strengthInBytes = strengthInBits / bitsPerByte;

                byte[] data = new byte[strengthInBytes];
                _random.GetBytes(data);
                return HttpServerUtility.UrlTokenEncode(data);
            }
        }

        #endregion
        #region UserManager
        [Authorize(Roles = "admin")]
        [Route("users/{id:guid}/roles")]
        [HttpPut]
        public async Task<IHttpActionResult> AssignRolesToUser(string id, string[] rolesToAssign)
        {
            if (rolesToAssign == null)
            {
                return this.BadRequest("No roles specified");
            }

            ///find the user we want to assign roles to
            var appUser = await this.UserManager.FindByIdAsync(id);

            if (appUser == null || appUser.IsDeleted)
            {
                return NotFound();
            }

            ///check if the user currently has any roles
            var currentRoles = await this.UserManager.GetRolesAsync(appUser.Id);


            var rolesNotExist = rolesToAssign.Except(this.RoleManager.Roles.Select(x => x.Name)).ToArray();

            if (rolesNotExist.Count() > 0)
            {
                ModelState.AddModelError("", string.Format("Roles '{0}' does not exist in the system", string.Join(",", rolesNotExist)));
                return this.BadRequest(ModelState);
            }

            ///remove user from current roles, if any
            IdentityResult removeResult = await this.UserManager.RemoveFromRolesAsync(appUser.Id, currentRoles.ToArray());


            if (!removeResult.Succeeded)
            {
                ModelState.AddModelError("", "Failed to remove user roles");
                return BadRequest(ModelState);
            }

            ///assign user to the new roles
            IdentityResult addResult = await this.UserManager.AddToRolesAsync(appUser.Id, rolesToAssign);

            if (!addResult.Succeeded)
            {
                ModelState.AddModelError("", "Failed to add user roles");
                return BadRequest(ModelState);
            }

            return Ok(new { userId = id, rolesAssigned = rolesToAssign });
        }
        [Authorize(Roles = "admin")]
        [HttpDelete]
        [Route("user/{id:guid}")]
        public IHttpActionResult DeleteUser(string id)
        {
            //check if such a user exists in the database
            var userToDelete = this.UserManager.FindById(id);
            if (userToDelete == null)
            {
                return this.NotFound();
            }
            else if (userToDelete.IsDeleted)
            {
                return this.BadRequest("User already deleted");
            }
            else
            {
                var con = ConfigurationManager.ConnectionStrings["DefaultConnection"].ConnectionString;
                using (SqlConnection connection = new SqlConnection(con))
                {
                    using (SqlCommand command = new SqlCommand("UPDATE dbo.AspNetUsers SET IsDeleted = 1 WHERE Id = @UserId", connection))
                    {
                        command.Parameters.Add("@UserId", SqlDbType.NVarChar).Value = id;
                        connection.Open();
                        command.ExecuteNonQuery();
                        connection.Close();
                    }
                }
            }
            return this.Ok();
        }
        [AllowAnonymous]
        [HttpGet]
        [Route("UserConfirm/{activationCode:guid}")]
        public IHttpActionResult UserConfirm(Guid activationCode)
        {
            //check if such a user exists in the database
            ApplicationDbContext context = new ApplicationDbContext();
            var userToConfirm = context.Users.Where(x => x.Activation == activationCode).FirstOrDefault();
            if (userToConfirm == null)
            {
                return this.NotFound();
            }
            else if (userToConfirm.IsDeleted)
            {
                return this.BadRequest("User already deleted");
            }
            else
            {
                var con = ConfigurationManager.ConnectionStrings["DefaultConnection"].ConnectionString;
                using (SqlConnection connection = new SqlConnection(con))
                {
                    using (SqlCommand command = new SqlCommand("UPDATE dbo.AspNetUsers SET IsActive = 1 WHERE Id = @UserId", connection))
                    {
                        command.Parameters.Add("@UserId", SqlDbType.NVarChar).Value = userToConfirm.Id;
                        connection.Open();
                        command.ExecuteNonQuery();
                        connection.Close();
                    }
                }
            }
            return this.Ok("Your account activated successfully");
        }
        #endregion
    }
}
