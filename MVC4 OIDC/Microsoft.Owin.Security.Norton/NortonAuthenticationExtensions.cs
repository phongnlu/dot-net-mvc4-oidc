using System;
using Microsoft.Owin.Security.Norton;

namespace Owin
{
    /// <summary>
    /// Extension methods for using <see cref="NortonAuthenticationMiddleware"/>
    /// </summary>
    public static class NortonAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using Norton
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>        
        public static IAppBuilder UseNortonAuthentication(this IAppBuilder app, NortonAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(NortonAuthenticationMiddleware), app, options);
            return app;
        }

        /// <summary>
        /// Authenticate users using Norton
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="clientId">The Norton assigned client id</param>
        /// <param name="clientSecret">The Norton assigned client secret</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>        
        public static IAppBuilder UseNortonAuthentication(
            this IAppBuilder app,
            string clientId,
            string clientSecret)
        {
            return UseNortonAuthentication(
                app,
                new NortonAuthenticationOptions
                {
                    ClientId = clientId,
                    ClientSecret = clientSecret
                });
        }
    }
}