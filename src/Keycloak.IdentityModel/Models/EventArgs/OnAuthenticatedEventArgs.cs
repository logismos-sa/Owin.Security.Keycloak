using System;

namespace Keycloak.IdentityModel.Models.EventArgs
{
    public class OnAuthenticatedEventArgs : System.EventArgs
    {
        public string RedirectUri { get; set; }
    }
    public class OnSecurityExceptionArgs : System.EventArgs
    {
        public string Message { get; set; }
        public Type Exception { get; set; }
    }
}
