using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(MVC4_OIDC.Startup))]
namespace MVC4_OIDC
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
