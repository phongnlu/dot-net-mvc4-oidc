using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;

namespace Microsoft.Owin.Security.Norton
{
    internal class NortonAuthenticationHandler : AuthenticationHandler<NortonAuthenticationOptions>
    {
        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public NortonAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(Options.CookieManager, properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                // Build up the body for the token request
                var body = new List<KeyValuePair<string, string>>();
                body.Add(new KeyValuePair<string, string>("grant_type", "authorization_code"));
                body.Add(new KeyValuePair<string, string>("code", code));
                body.Add(new KeyValuePair<string, string>("redirect_uri", redirectUri));
                body.Add(new KeyValuePair<string, string>("client_id", Options.ClientId));
                body.Add(new KeyValuePair<string, string>("client_secret", Options.ClientSecret));

                // Request the token
                HttpResponseMessage tokenResponse =
                    await _httpClient.PostAsync(Options.TokenEndpoint, new FormUrlEncodedContent(body));
                tokenResponse.EnsureSuccessStatusCode();
                string text = await tokenResponse.Content.ReadAsStringAsync();

                // Deserializes the token response
                JObject response = JObject.Parse(text);
                string idToken = response.Value<string>("id_token");
                if (string.IsNullOrWhiteSpace(idToken))
                {
                    _logger.WriteWarning("Id token was not found");
                    return new AuthenticationTicket(null, properties);
                }
                string accessToken = response.Value<string>("access_token");
                if (string.IsNullOrWhiteSpace(accessToken))
                {
                    _logger.WriteWarning("Access token was not found");
                    return new AuthenticationTicket(null, properties);
                }
                string refreshToken = response.Value<string>("refresh_token");
                if (string.IsNullOrWhiteSpace(refreshToken))
                {
                    _logger.WriteWarning("Refresh token was not found");
                    return new AuthenticationTicket(null, properties);
                }
                int expiresIn = response.Value<int>("expires_in");

                //open up id_token
                var handler = new JwtSecurityTokenHandler();
                var token = handler.ReadToken(idToken) as JwtSecurityToken;
                var id = token.Claims.First(c => c.Type == "sub").Value;
                var email = token.Claims.First(c => c.Type == "email").Value;

                var context = new NortonAuthenticatedContext(Context, id, email, idToken, accessToken, refreshToken, expiresIn);
                context.Identity = new ClaimsIdentity(
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);

                if (!string.IsNullOrEmpty(context.Id))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id,
                        ClaimValueTypes.String, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Email))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, ClaimValueTypes.String,
                        Options.AuthenticationType));
                }
                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError("Authentication failed", ex);
                return new AuthenticationTicket(null, properties);
            }
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string baseUri =
                    Request.Scheme +
                    Uri.SchemeDelimiter +
                    Request.Host +
                    Request.PathBase;

                string currentUri =
                    baseUri +
                    Request.Path +
                    Request.QueryString;

                string redirectUri =
                    baseUri +
                    Options.CallbackPath;

                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(Options.CookieManager, properties);

                var queryStrings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                queryStrings.Add("response_type", "code");
                queryStrings.Add("client_id", Options.ClientId);
                queryStrings.Add("redirect_uri", redirectUri);                

                var acrValues = string.Join(" ", Options.AcrValues);
                if (!string.IsNullOrEmpty(acrValues))
                {
                    queryStrings.Add("acr_values", acrValues);
                }

                // space separated
                string scope = string.Join(" ", Options.Scope);
                if (string.IsNullOrEmpty(scope))
                {                    
                    scope = "openid email";
                }
                AddQueryString(queryStrings, properties, "scope", scope);

                AddQueryString(queryStrings, properties, "access_type", Options.AccessType);
                AddQueryString(queryStrings, properties, "approval_prompt");
                AddQueryString(queryStrings, properties, "prompt");
                AddQueryString(queryStrings, properties, "login_hint");
                AddQueryString(queryStrings, properties, "include_granted_scopes");

                string state = Options.StateDataFormat.Protect(properties);
                queryStrings.Add("state", state);

                string authorizationEndpoint = WebUtilities.AddQueryString(Options.AuthorizationEndpoint,
                    queryStrings);

                var redirectContext = new NortonApplyRedirectContext(
                    Context, Options,
                    properties, authorizationEndpoint);
                Options.Provider.ApplyRedirect(redirectContext);
            }

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                // TODO: error responses

                AuthenticationTicket ticket = await AuthenticateAsync();
                if (ticket == null)
                {
                    _logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new NortonReturnEndpointContext(Context, ticket);
                context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
                context.RedirectUri = ticket.Properties.RedirectUri;

                await Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null &&
                    context.Identity != null)
                {
                    ClaimsIdentity grantIdentity = context.Identity;
                    if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                    }
                    Context.Authentication.SignIn(context.Properties, grantIdentity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    string redirectUri = context.RedirectUri;
                    if (context.Identity == null)
                    {
                        // add a redirect hint that sign-in failed in some way
                        redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
                    }
                    Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
            }
            return false;
        }

        private static void AddQueryString(IDictionary<string, string> queryStrings, AuthenticationProperties properties,
            string name, string defaultValue = null)
        {
            string value;
            if (!properties.Dictionary.TryGetValue(name, out value))
            {
                value = defaultValue;
            }
            else
            {
                // Remove the parameter from AuthenticationProperties so it won't be serialized to state parameter
                properties.Dictionary.Remove(name);
            }

            if (value == null)
            {
                return;
            }

            queryStrings[name] = value;
        }
    }
}