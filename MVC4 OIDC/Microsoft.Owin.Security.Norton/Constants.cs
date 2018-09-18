using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Microsoft.Owin.Security.Norton
{
    internal static class Constants
    {
        internal const string DefaultAuthenticationType = "Norton";       
        internal const string AuthorizationEndpoint = "https://login.norton.com/sso/idp/OIDC";
        internal const string TokenEndpoint = "https://login.norton.com/sso/oidc1/tokens";
        internal const string UserInformationEndpoint = "https://login.norton.com/sso/oidc1/userinfo";
    }
}