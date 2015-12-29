using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Web;
using System.Web.Http;
using System.Web.Http.Controllers;

namespace Spark.HIS.Security
{
    public class STSAuthorizationFilter : AuthorizeAttribute
    {

        /// <summary>
        /// Indicates whether the specified control is authorized.
        /// </summary>
        /// <param name="actionContext">The context.</param>
        /// <returns>
        /// true if the control is authorized; otherwise, false.
        /// </returns>
        protected override bool IsAuthorized(HttpActionContext actionContext)
        {
            //Grab the identity and authenticate it

            var identity = Thread.CurrentPrincipal.Identity;
            if (identity == null && HttpContext.Current != null)
                identity = HttpContext.Current.User.Identity;

            if (identity != null && identity.IsAuthenticated)
            {
                var basicAuth = identity as STSAuthenticationIdentity;

                //TODO: business authorization as needed
            }

            //TODO: always return true for now
            return true;
        }
    }
}