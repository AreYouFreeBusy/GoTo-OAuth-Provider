//  Copyright 2017 Stefan Negritoiu (FreeBusy). See LICENSE file for more information.

using System;

namespace Owin.Security.Providers.GoTo
{
    public static class GoToAuthenticationExtensions
    {
        public static IAppBuilder UseGoToAuthentication(this IAppBuilder app, GoToAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(GoToAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseGoToAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseGoToAuthentication(new GoToAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}