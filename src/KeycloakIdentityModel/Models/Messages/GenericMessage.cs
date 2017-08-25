using System;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Threading.Tasks;
using KeycloakIdentityModel.Models.Configuration;

namespace KeycloakIdentityModel.Models.Messages
{
    public abstract class GenericMessage<T>
    {
        private readonly log4net.ILog _logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

        protected GenericMessage(IKeycloakParameters options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            Options = options;
        }

        protected IKeycloakParameters Options { get; }
        public abstract Task<T> ExecuteAsync();

        protected async Task<HttpResponseMessage> SendHttpPostRequest(Uri uri, HttpContent content = null)
        {
            HttpResponseMessage response;
            try
            {
                var client = new HttpClient();
                response = await client.PostAsync(uri, content);
            }
            catch (Exception exception)
            {
                throw new Exception("HTTP client URI is inaccessible", exception);
            }

            // Check for HTTP errors
            if (response.StatusCode == HttpStatusCode.BadRequest) {
                _logger.Error($"HTTP client response returned error {response.ReasonPhrase}/{(int)response.StatusCode}.");
                throw new AuthenticationException(); // Assume bad credentials
            }

            //if (!response.IsSuccessStatusCode)
            //{
            //    _logger.Error($"HTTP client response error {response.ReasonPhrase}/{response.StatusCode}.");
            //    throw new Exception("HTTP client returned an unrecoverable error");
            //}
            return response;
        }

        protected async Task<string> ReadHttpResponseAsync(HttpResponseMessage response)
        {
            var result = await response.Content.ReadAsStringAsync();
            if (!response.IsSuccessStatusCode)
            {
                _logger.Error($"HTTP client response returned error {result}.");
                throw new Exception("HTTP client returned an unrecoverable error");
            }
            return result;
        }

    }
}