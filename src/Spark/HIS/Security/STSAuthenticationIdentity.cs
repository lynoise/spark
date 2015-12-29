using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Web;

namespace Spark.HIS.Security
{
    public class STSAuthenticationIdentity : GenericIdentity
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="STSAuthenticationIdentity" /> class.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <param name="password">The password.</param>
        //TODO:constructor will need to change as STS auth does not expect a user/password combination
        public STSAuthenticationIdentity(string name, string password)
            : base(name, "STS")
        {            
            //TODO:there is no pasword with STS cert auth
            this.Password = password;
        }

        /// <summary>
        /// Basic Auth Password for custom authentication
        /// </summary>
        /// <value>
        /// The password.
        /// </value>
        public string Password { get; set; }

        /// <summary>
        /// Gets a value indicating whether the user has been authenticated.
        /// </summary>
        public override bool IsAuthenticated
        {
            get
            {
                //TODO: validate the STS information (token/cert?)
                //Always returns true for now
                return base.IsAuthenticated && true;
            }
        }

    }


}