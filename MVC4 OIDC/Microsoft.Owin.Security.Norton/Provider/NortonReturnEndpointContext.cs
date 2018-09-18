using Microsoft.Owin.Security.Provider;

namespace Microsoft.Owin.Security.Norton
{
    /// <summary>
    /// Provides context information to middleware providers.
    /// </summary>
    public class NortonReturnEndpointContext : ReturnEndpointContext
    {
        /// <summary>
        /// Initialize a <see cref="NortonReturnEndpointContext"/>
        /// </summary>
        /// <param name="context">OWIN environment</param>
        /// <param name="ticket">The authentication ticket</param>
        public NortonReturnEndpointContext(
            IOwinContext context,
            AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}