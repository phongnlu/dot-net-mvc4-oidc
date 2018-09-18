﻿using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Norton
{
    /// <summary>
    /// Specifies callback methods which the <see cref="NortonAuthenticationMiddleware"></see> invokes to enable developer control over the authentication process. />
    /// </summary>
    public interface INortonAuthenticationProvider
    {
        /// <summary>
        /// Invoked whenever Norton succesfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task Authenticated(NortonAuthenticatedContext context);

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context">Contains context information and authentication ticket of the return endpoint.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task ReturnEndpoint(NortonReturnEndpointContext context);

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint in the Norton middleware
        /// </summary>
        /// <param name="context">Contains redirect URI and <see cref="AuthenticationProperties"/> of the challenge </param>
        void ApplyRedirect(NortonApplyRedirectContext context);
    }
}