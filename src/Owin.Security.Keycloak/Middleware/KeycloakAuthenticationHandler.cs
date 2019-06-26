using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IdentityModel;
using System.Linq;
using System.Net;
using System.Security.Authentication;
using System.Security.Claims;
using System.Threading.Tasks;
using Keycloak.IdentityModel;
using Keycloak.IdentityModel.Models.EventArgs;
using Keycloak.IdentityModel.Models.Responses;
using Keycloak.IdentityModel.Utilities;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.Keycloak.Middleware
{
    internal class KeycloakAuthenticationHandler : AuthenticationHandler<KeycloakAuthenticationOptions>
    {
        private readonly log4net.ILog _logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            // Bearer token authentication override
            if (Options.EnableBearerTokenAuth)
            {
                // Try to authenticate via bearer token auth
                if (Request.Headers.ContainsKey(Constants.BearerTokenHeader))
                {
                    var bearerAuthArr = Request.Headers[Constants.BearerTokenHeader].Trim().Split(new[] {' '}, 2);
                    if ((bearerAuthArr.Length == 2) && bearerAuthArr[0].ToLowerInvariant() == "bearer")
                    {
                        try
                        {
                            var authResponse = new TokenResponse(bearerAuthArr[1], null, null);
                            var kcIdentity = await KeycloakIdentity.ConvertFromTokenResponseAsync(Options, authResponse);
                            var identity = await kcIdentity.ToClaimsIdentityAsync();
                            SignInAsAuthentication(identity, null, Options.SignInAsAuthenticationType);
                            return new AuthenticationTicket(identity, new AuthenticationProperties());
                        }
                        catch (Exception)
                        {
                            // ignored
                        }
                    }
                }

                // If bearer token auth is forced, skip standard auth
                if (Options.ForceBearerTokenAuth) return null;
            }

            return null;
        }

        [DebuggerStepThrough]
        public override async Task<bool> InvokeAsync()
        {
            // Check SignInAs identity for authentication update
            if (Context.Authentication.User.Identity.IsAuthenticated)
            {
                await ValidateSignInAsIdentities();
            }

            // Check for valid callback URI
            var callbackUri = await KeycloakIdentity.GenerateLoginCallbackUriAsync(Options, Request.Uri);

            if (!Options.ForceBearerTokenAuth && Request.Uri.GetLeftPart(UriPartial.Path) == callbackUri.ToString())
            {
                // Create authorization result from query
                var authResult = new AuthorizationResponse(Request.Uri.Query);
                _logger.Debug($"Request from {Request.Uri}");

                try
                {
                    // Validate passed state
                    var stateData = Global.StateCache.ReturnState(authResult.State) ?? new Dictionary<string, object>();
                    //throw new BadRequestException("Invalid state: Please reattempt the request");

                    // Process response and gather claims. If No state is found in cache we will log out the user from Keycloak and redirect him
                    //again for login. StateData must exist and match the oidc_state received from request
                    var kcIdentity =
                        await KeycloakIdentity.ConvertFromAuthResponseAsync(Options, authResult, Request.Uri);
                    var identity = await kcIdentity.ToClaimsIdentityAsync();
                    
                    if (!stateData.ContainsKey(Constants.CacheTypes.AuthenticationProperties))
                    {
                        await ForceLogoutRedirectAsync(identity);
                        _logger.Debug($"State data is null.Logging out user and redirecting");
                        return true;
                    }

                    // Parse properties from state data
                    var properties = stateData[Constants.CacheTypes.AuthenticationProperties] as AuthenticationProperties;
                    
                    //everything is ok until here, sign in the user
                    Context.Authentication.User = new ClaimsPrincipal(identity);
                    SignInAsAuthentication(identity, properties, Options.SignInAsAuthenticationType);
                    _logger.Debug($"Signed in user {identity.Name} with state data.");

                    // Trigger OnAuthenticated?
                    var eventArgs = new OnAuthenticatedEventArgs { RedirectUri = properties?.RedirectUri };
                    Options.OnAuthenticated?.Invoke(Context, eventArgs);

                    // Redirect back to the original secured resource, if any
                    if (!string.IsNullOrWhiteSpace(eventArgs.RedirectUri) &&
                        Uri.IsWellFormedUriString(eventArgs.RedirectUri, UriKind.Absolute))
                    {
                        Response.Redirect(eventArgs.RedirectUri);
                        return true;
                    }
                }
                catch (Exception exception)
                {
                    _logger.Debug($"Returning false for {exception.Message} {exception.StackTrace}");
                    await GenerateErrorResponseAsync(HttpStatusCode.InternalServerError, "Internal Server Error", exception.Message);
                    return false;
                }
            }

            return false;
        }

        protected override async Task ApplyResponseGrantAsync()
        {
            if (Options.ForceBearerTokenAuth) return;

            var signout = Helper.LookupSignOut(Options.AuthenticationType, Options.AuthenticationMode);

            // Signout takes precedence
            if (signout != null)
            {
                await LogoutRedirectAsync();
            }
        }

        protected override async Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode == 401)
            {
                // If bearer token auth is forced, keep returned 401
                if (Options.ForceBearerTokenAuth)
                {
                    await
                        GenerateUnauthorizedResponseAsync(
                            "Access Unauthorized: Requires valid bearer token authorization header");
                    return;
                }

                var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
                if (challenge == null) return;

                _logger.Debug($"ApplyResponseChallengeAsync for 401.Redirecting");
                await LoginRedirectAsync(challenge.Properties);
            }
        }

        #region Private Helper Functions

        private void SignInAsAuthentication(ClaimsIdentity identity, AuthenticationProperties authProperties = null,
            string signInAuthType = null)
        {
            if (signInAuthType == Options.AuthenticationType) return;

            var signInIdentity = signInAuthType != null
                ? new ClaimsIdentity(identity.Claims, signInAuthType, identity.NameClaimType, identity.RoleClaimType)
                : identity;

            if (string.IsNullOrWhiteSpace(signInIdentity.AuthenticationType)) return;

            if (authProperties == null)
            {
                authProperties = new AuthenticationProperties
                {
                    // TODO: Make these configurable
                    AllowRefresh = true,
                    IsPersistent = true,
                    ExpiresUtc = DateTime.Now.Add(Options.SignInAsAuthenticationExpiration)
                };
            }
            
            // Parse expiration date-time
            var expirations = new List<string>
            {
                identity.Claims.FirstOrDefault(c => c.Type == Constants.ClaimTypes.RefreshTokenExpiration)?.Value,
                identity.Claims.FirstOrDefault(c => c.Type == Constants.ClaimTypes.AccessTokenExpiration)?.Value
            };
            
            foreach (var expStr in expirations)
            {
                DateTime expDate;
                if (expStr == null ||
                    !DateTime.TryParse(expStr, CultureInfo.InvariantCulture, DateTimeStyles.None, out expDate))
                    continue;
                authProperties.ExpiresUtc = expDate.Add(Options.TokenClockSkew);
                break;
            }

            Context.Authentication.SignIn(authProperties, signInIdentity);
        }

        private async Task ValidateSignInAsIdentities()
        {
            foreach (var origIdentity in Context.Authentication.User.Identities)
            {
                try
                {
                    if (!origIdentity.HasClaim(Constants.ClaimTypes.AuthenticationType, Options.AuthenticationType))
                        continue;
                    var kcIdentity = await KeycloakIdentity.ConvertFromClaimsIdentityAsync(Options, origIdentity);
                    if (!kcIdentity.IsTouched) continue;

                    // Replace identity if expired
                    var identity = await kcIdentity.ToClaimsIdentityAsync();
                    Context.Authentication.User = new ClaimsPrincipal(identity);
                    SignInAsAuthentication(identity, null, Options.SignInAsAuthenticationType);

                    _logger.Debug($"Identity isTouched. Signing refreshed identity {identity.Name}");
                }
                catch (AuthenticationException)
                {
                    Context.Authentication.SignOut(origIdentity.AuthenticationType);
                }
                // ReSharper disable once RedundantCatchClause
                catch (Exception)
                {
                    // TODO: Some kind of exception logging, maybe log the user out
                    throw;
                }
            }
        }

        private async Task GenerateUnauthorizedResponseAsync(string errorMessage)
        {
            await GenerateErrorResponseAsync(Response, HttpStatusCode.Unauthorized, "Unauthorized", errorMessage);
        }

        private async Task GenerateErrorResponseAsync(HttpStatusCode statusCode, string reasonPhrase,
            string errorMessage)
        {
            await GenerateErrorResponseAsync(Response, statusCode, reasonPhrase, errorMessage);
        }

        private static async Task GenerateErrorResponseAsync(IOwinResponse response, HttpStatusCode statusCode,
            string reasonPhrase, string errorMessage)
        {
            // Generate error response
            var task = response.WriteAsync(errorMessage);
            response.StatusCode = (int) statusCode;
            response.ReasonPhrase = reasonPhrase;
            response.ContentType = "text/plain";
            await task;
        }

        #endregion

        #region OIDC Helper Functions

        private async Task LoginRedirectAsync(AuthenticationProperties properties)
        {
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = Request.Uri.ToString();
            }

            // Create state
            var stateData = new Dictionary<string, object>
            {
                {Constants.CacheTypes.AuthenticationProperties, properties}
            };
            var state = Global.StateCache.CreateState(stateData);

            _logger.Debug($"Login redirect async: created state for uri {properties.RedirectUri} and redirecting");
            // Redirect response to login
            Response.Redirect((await KeycloakIdentity.GenerateLoginUriAsync(Options, Request.Uri, state)).ToString());
        }

        private async Task LogoutRedirectAsync()
        {
            // Redirect response to logout
            Response.Redirect(
                (await
                    KeycloakIdentity.GenerateLogoutUriAsync(Options, Request.Uri))
                    .ToString());
        }

        /// <summary>
        /// Method logs generates the logout url for the realm and performs a user log out 
        /// and issues a redirection to the login page for the user to enter credentials again.
        /// </summary>
        /// <param name="identity">Current identity signed in keycloak. It will be forced log out.</param>
        /// <returns>Redirection to login page</returns>
        private async Task ForceLogoutRedirectAsync(ClaimsIdentity identity)
        {
            // generate logout uri
            var uri = await KeycloakIdentity.GenerateLogoutUriAsync(Options, Request.Uri);
            //foreach (var claim in identity.Claims)
            //{
            //    _logger.Debug($"ForceLogoutRedirectAsync user claim {claim.Type} - {claim.Value}");
            //}
          
            _logger.Debug($"Force logout identity with isAuthenticated:{identity.IsAuthenticated}");

            Claim firstOrDefault = identity.Claims.FirstOrDefault(claim => claim.Type == "refresh_token");
            if (firstOrDefault != null)
            {
                await OidcDataManager.HttpLogoutPost(firstOrDefault.Value, Options, uri);
            }
            
            //redirect to relogin
            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge == null)
            {
                _logger.Debug($"Force logged out {identity.Name}.Challenge is null.Return.");
                return;
            }

            _logger.Debug($"Force logged out {identity.Name}.Redirecting from challenge properties.");
            await LoginRedirectAsync(challenge.Properties);
        }

        #endregion
    }
}