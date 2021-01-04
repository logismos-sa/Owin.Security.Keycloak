using System;

namespace Keycloak.IdentityModel.Models.Configuration
{
    public interface IKeycloakParameters
    {
        string AuthenticationType { get; }
        string KeycloakUrl { get; }
        string Realm { get; }
        string ClientId { get; }
        string ClientSecret { get; }
        string Scope { get; }
        string IdentityProvider { get; }
        string PostLogoutRedirectUrl { get; }
        bool DisableTokenSignatureValidation { get; }
        bool AllowUnsignedTokens { get; }
        bool DisableIssuerValidation { get; }
        bool DisableAudienceValidation { get; }
        bool UseRemoteTokenValidation { get; }
        TimeSpan TokenClockSkew { get; }
        TimeSpan MetadataRefreshInterval { get; }
        TimeSpan RefreshBeforeTokenExpiration { get; set; }
        string CallbackPath { get; }
        string ResponseType { get; }
        bool DisableRefreshTokenSignatureValidation { get; }
        bool DisableAllRefreshTokenValidation { get; }
        string AuthResponseErrorRedirectUrl { get; }

        string UiLocales { get; set; }
    }
}
