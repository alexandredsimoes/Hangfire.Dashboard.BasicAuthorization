using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace Hangfire.Dashboard.BasicAuthorization
{
    public class IdentityAuthAuthorizationFilter : IDashboardAuthorizationFilter
    {
        private readonly BasicAuthAuthorizationFilterOptions _options;

        public IdentityAuthAuthorizationFilter()
            : this(new BasicAuthAuthorizationFilterOptions())
        {
        }

        public IdentityAuthAuthorizationFilter(BasicAuthAuthorizationFilterOptions options )
        {
            _options = options;
        }

        public bool Authorize(DashboardContext context)
        {

            var httpContext = context.GetHttpContext();
            if ((_options.SslRedirect == true) && (httpContext.Request.Scheme != "https"))
            {
                string redirectUri = new UriBuilder("https", httpContext.Request.Host.ToString(), 443, httpContext.Request.Path).ToString();

                httpContext.Response.StatusCode = 301;
                httpContext.Response.Redirect(redirectUri);
                return false;
            }

            if ((_options.RequireSsl == true) && (httpContext.Request.IsHttps == false))
            {
                return false;
            }

            if (httpContext.User.Identity.IsAuthenticated)
            {
                return !_options.Roles.Any() || _options.Roles.Any(role => httpContext.User.IsInRole(role));
            }
            httpContext.Response.StatusCode = 301;
            httpContext.Response.Redirect("/login", true);
            return false;


            string header = httpContext.Request.Headers["Authorization"];

            if (String.IsNullOrWhiteSpace(header) == false)
            {
                AuthenticationHeaderValue authValues = AuthenticationHeaderValue.Parse(header);

                if ("Basic".Equals(authValues.Scheme, StringComparison.OrdinalIgnoreCase))
                {
                    string parameter = Encoding.UTF8.GetString(Convert.FromBase64String(authValues.Parameter));
                    var parts = parameter.Split(':');

                    if (parts.Length > 1)
                    {
                        string login = parts[0];
                        string password = parts[1];

                        if ((String.IsNullOrWhiteSpace(login) == false) && (String.IsNullOrWhiteSpace(password) == false))
                        {
                            return _options
                                       .Users
                                       .Any(user => user.Validate(login, password, _options.LoginCaseSensitive))
                                   || Challenge(httpContext);
                        }
                    }
                }
            }

            return Challenge(httpContext);
        }

        private bool Challenge(HttpContext context)
        {
            context.Response.StatusCode = 401;
            context.Response.Headers.Append("WWW-Authenticate", "Basic realm=\"Hangfire Dashboard\"");
            return false;
        }
    }
}
