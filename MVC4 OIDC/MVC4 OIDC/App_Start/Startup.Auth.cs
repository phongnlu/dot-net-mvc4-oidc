using Microsoft.Owin;
using Owin;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security.Cookies;
using System.Web.Helpers;
using System.Security.Claims;

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

            var googleClientId = "835072215661-etftrpjnap9bp5ouu6bu58h6qa7ifg84.apps.googleusercontent.com";
            var googleClientSecret = "KGZgMjMTUihLLLgsLzNA2PH2";
            app.UseGoogleAuthentication(clientId: googleClientId, clientSecret: googleClientSecret);

            AntiForgeryConfig.UniqueClaimTypeIdentifier = ClaimTypes.NameIdentifier;
        }
    }
}