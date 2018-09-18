using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security.Norton
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class NortonAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="NortonAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized Norton user info</param>
        /// <param name="accessToken">Norton access token</param>
        /// <param name="refreshToken">Norton refresh token</param>
        /// <param name="expires">Seconds until expiration</param>
        public NortonAuthenticatedContext(IOwinContext context, JObject user, string accessToken,
            string refreshToken, string expires)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;
            RefreshToken = refreshToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            Id = TryGetValue(user, "id");
            Name = TryGetValue(user, "displayName");
            GivenName = TryGetValue(user, "name", "givenName");
            FamilyName = TryGetValue(user, "name", "familyName");
            Profile = TryGetValue(user, "url");
            Email = TryGetFirstValue(user, "emails", "value"); // TODO:
        }

        /// <summary>
        /// Initializes a <see cref="NortonAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized Norton user info</param>
        /// <param name="tokenResponse">The JSON-serialized token response Norton</param>
        public NortonAuthenticatedContext(IOwinContext context, JObject user, JObject tokenResponse)
            : base(context)
        {
            User = user;
            TokenResponse = tokenResponse;
            if (tokenResponse != null)
            {
                AccessToken = tokenResponse.Value<string>("access_token");
                RefreshToken = tokenResponse.Value<string>("refresh_token");

                int expiresValue;
                if (Int32.TryParse(tokenResponse.Value<string>("expires_in"), NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
                {
                    ExpiresIn = TimeSpan.FromSeconds(expiresValue);
                }
            }

            Id = TryGetValue(user, "id");
            Name = TryGetValue(user, "displayName");
            GivenName = TryGetValue(user, "name", "givenName");
            FamilyName = TryGetValue(user, "name", "familyName");
            Profile = TryGetValue(user, "url");
            Email = TryGetFirstValue(user, "emails", "value"); // TODO:
        }

        /// <summary>
        /// Initializes a <see cref="NortonAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="id">The user Id</param>
        /// <param name="email">The user email</param>
        /// <param name="idToken">Norton id token</param>
        /// <param name="accessToken">Norton access token</param>
        /// <param name="refreshToken">Norton refresh token</param>
        /// <param name="expires">Seconds until expiration</param>
        public NortonAuthenticatedContext(IOwinContext context, string id, string email, string idToken, string accessToken, string refreshToken, int expires)
            : base(context)
        {
            ExpiresIn = TimeSpan.FromSeconds(expires);
            Id = id;
            Email = email;
            IdToken = idToken;
            AccessToken = accessToken;
            RefreshToken = refreshToken;         
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Norton user obtained from the endpoint https://login.norton.com/sso/oidc1/userinfo
        /// </remarks>
        public JObject User { get; private set; }


        /// <summary>
        /// Gets the Norton id token
        /// </summary>
        public string IdToken { get; private set; }

        /// <summary>
        /// Gets the Norton access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Norton refresh token
        /// </summary>
        /// <remarks>
        /// This value is not null only when access_type authorize parameter is offline.
        /// </remarks>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Gets the Norton access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets the Norton user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the user's given name
        /// </summary>
        public string GivenName { get; set; }

        /// <summary>
        /// Gets the user's family name
        /// </summary>
        public string FamilyName { get; set; }

        /// <summary>
        /// Gets the user's profile link
        /// </summary>
        public string Profile { get; private set; }

        /// <summary>
        /// Gets the user's email
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Token response from Norton
        /// </summary>
        public JObject TokenResponse { get; private set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }

        // Get the given subProperty from a property.
        private static string TryGetValue(JObject user, string propertyName, string subProperty)
        {
            JToken value;
            if (user.TryGetValue(propertyName, out value))
            {
                var subObject = JObject.Parse(value.ToString());
                if (subObject != null && subObject.TryGetValue(subProperty, out value))
                {
                    return value.ToString();
                }
            }
            return null;
        }

        // Get the given subProperty from a list property.
        private static string TryGetFirstValue(JObject user, string propertyName, string subProperty)
        {
            JToken value;
            if (user.TryGetValue(propertyName, out value))
            {
                var array = JArray.Parse(value.ToString());
                if (array != null && array.Count > 0)
                {
                    var subObject = JObject.Parse(array.First.ToString());
                    if (subObject != null)
                    {
                        if (subObject.TryGetValue(subProperty, out value))
                        {
                            return value.ToString();
                        }
                    }
                }
            }
            return null;
        }
    }
}