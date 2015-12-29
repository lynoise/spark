using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace Spark.HIS.Security
{
    public class STSAuthenticationHandler : DelegatingHandler
    {
        //TODO:needed with STS auth?
        private const string WWWAuthenticateHeader = "WWW-Authenticate";

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
                                                               CancellationToken cancellationToken)
        {
            var credentials = ParseAuthorizationHeader(request);

            if (credentials != null)
            {
                var identity = new STSAuthenticationIdentity(credentials.Name, credentials.Password);
                var principal = new GenericPrincipal(identity, null);

                Thread.CurrentPrincipal = principal;
                if (HttpContext.Current != null)
                    HttpContext.Current.User = principal;
            }

            return base.SendAsync(request, cancellationToken)
                .ContinueWith(task =>
                {
                    var response = task.Result;
                    if (credentials == null && response.StatusCode == HttpStatusCode.Unauthorized)
                        Challenge(request, response);

                    return response;
                });
        }

        /// <summary>
        /// Parses the Authorization header and creates user credentials
        /// </summary>
        /// <param name="request">The request.</param>
        /// <returns></returns>
        protected virtual STSAuthenticationIdentity ParseAuthorizationHeader(HttpRequestMessage request)
        {
            //TODO: get STS infromation and setup the STS authenticationIdentity object 
            //All of the header stuff here may be throw away (depends on how STS expects it)

            string authHeader = null;
            var auth = request.Headers.Authorization;
            if (auth != null && auth.Scheme == "Basic")
                authHeader = auth.Parameter;

            if (string.IsNullOrEmpty(authHeader))
                return null;

            authHeader = Encoding.Default.GetString(Convert.FromBase64String(authHeader));

            var tokens = authHeader.Split(':');
            if (tokens.Length < 2)
                return null;

            return new STSAuthenticationIdentity(tokens[0], tokens[1]);
        }


        /// <summary>
        /// Send the Authentication Challenge request
        /// </summary>
        /// <param name="message"></param>
        /// <param name="actionContext"></param>
        void Challenge(HttpRequestMessage request, HttpResponseMessage response)
        {
            //we are not doing browser basic auth so do not send the header requesting it
            //var host = request.RequestUri.DnsSafeHost;
            //response.Headers.Add(WWWAuthenticateHeader, string.Format("Basic realm=\"{0}\"", host));
        }

    }
}