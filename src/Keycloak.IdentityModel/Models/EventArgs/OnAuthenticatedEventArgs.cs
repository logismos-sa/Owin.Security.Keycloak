namespace Keycloak.IdentityModel.Models.EventArgs
{
    public class OnAuthenticatedEventArgs: System.EventArgs
    {
        public string RedirectUri { get; set; }
    }
}
