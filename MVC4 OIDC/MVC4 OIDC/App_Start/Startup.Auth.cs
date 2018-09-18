using Microsoft.Owin;
using Owin;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security.Cookies;
using System.Web.Helpers;
using System.Security.Claims;
using Microsoft.Owin.Security.Norton;
using System.Threading.Tasks;

namespace MVC4_OIDC
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Enable the application to use a cookie to store information for the signed in user
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/LogIn")
            });


            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);
            
            var nslClientId = "{{client_id}}";
            var nslClientSecret = "{{client_secret}}";
            app.UseNortonAuthentication(new NortonAuthenticationOptions()
            {
                ClientId = nslClientId,
                ClientSecret = nslClientSecret,
                AuthorizationEndpoint = "https://login-int.norton.com/sso/idp/OIDC",
                TokenEndpoint = "https://login-int.norton.com/sso/oidc1/tokens",
                UserInformationEndpoint = "https://login-int.norton.com/sso/oidc1/userinfo",
                CallbackPath = new PathString("/signin-norton"),
                AcrValues = "https://login.norton.com/sso/saml_2.0_profile/noheaderfooter https://login.norton.com/sso/saml_2.0_profile/nosignup",
                Provider = new NortonAuthenticationProvider()
                {
                    OnAuthenticated = async context =>
                    {
                        await Task.Run(() =>
                        {
                            //your code here
                            var accessToken = context.AccessToken;
                            var refreshToken = context.RefreshToken;
                            var idToken = context.IdToken;

                            return Task.FromResult(0);
                        });                        
                    },
                    OnReturnEndpoint = async context =>
                    {
                        await Task.Run(() =>
                        {
                            //your code here
                            return Task.FromResult(0);
                        });
                    },
                    OnApplyRedirect = context =>
                    {
                        //your code here
                        context.Response.Redirect(context.RedirectUri);
                    }
                }
            });            

            AntiForgeryConfig.UniqueClaimTypeIdentifier = ClaimTypes.NameIdentifier;
        }
    }
}