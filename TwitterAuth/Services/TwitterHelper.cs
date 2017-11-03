using Newtonsoft.Json;
using PCLCrypto;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using System.Linq;

namespace TwitterAuth.Services
{
    /// <summary>
    /// Modified version of https://garyshortblog.wordpress.com/2011/02/11/a-twitter-oauth-example-in-c/
    /// </summary>
    public static class TwitterHelper
    {
        private const string OAuthSignatureMethod = "HMAC-SHA1";
        private const string OAuthVersion = "1.0";

        public static async Task<T> GetAsync<T>(string consumerKey, string consumerSecret, string token, string tokenSecret, string url, SortedDictionary<string, string> parameters = null)
        {
            // Complete Url
            var completeUrl = url + (parameters != null && parameters.Count > 0 ? "?" + parameters.Select(x => $"{x.Key}={x.Value}").Aggregate((a, b) => $"{a}&{b}") : string.Empty);

            // Compute timestamps
            TimeSpan ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            string oauthnonce = Convert.ToBase64String(Encoding.UTF8.GetBytes(DateTime.Now.Ticks.ToString()));
            string oauthtimestamp = Convert.ToInt64(ts.TotalSeconds).ToString();

            // Prepare parameters
            SortedDictionary<string, string> basestringParameters = new SortedDictionary<string, string>();

            if (parameters != null && parameters.Count > 0)
            {
                foreach (var parameter in parameters)
                {
                    basestringParameters.Add(parameter.Key, parameter.Value);
                }
            }

            basestringParameters.Add("oauth_version", "1.0");
            basestringParameters.Add("oauth_consumer_key", consumerKey);
            basestringParameters.Add("oauth_nonce", oauthnonce);
            basestringParameters.Add("oauth_signature_method", "HMAC-SHA1");
            basestringParameters.Add("oauth_timestamp", oauthtimestamp);
            basestringParameters.Add("oauth_token", token);

            //GS - Build the signature string
            StringBuilder baseString = new StringBuilder();
            baseString.Append("GET" + "&");
            baseString.Append(EncodeCharacters(Uri.EscapeDataString(url) + "&"));
            foreach (KeyValuePair<string, string> entry in basestringParameters)
            {
                baseString.Append(EncodeCharacters(Uri.EscapeDataString(entry.Key + "=" + entry.Value + "&")));
            }

            //Since the baseString is urlEncoded we have to remove the last 3 chars - %26
            string finalBaseString = baseString.ToString().Substring(0, baseString.Length - 3);

            //Build the signing key
            string signingKey = EncodeCharacters(Uri.EscapeDataString(consumerSecret)) + "&" +
            EncodeCharacters(Uri.EscapeDataString(tokenSecret));

            //Sign the request
            var algorithm = WinRTCrypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha1);
            var hasher = algorithm.CreateHash(Encoding.UTF8.GetBytes(signingKey));
            hasher.Append(Encoding.UTF8.GetBytes(finalBaseString));
            string oauthsignature = Convert.ToBase64String(hasher.GetValueAndReset());

            //authorization header
            StringBuilder authorizationHeaderParams = new StringBuilder();
            authorizationHeaderParams.Append($"oauth_nonce=\"{Uri.EscapeDataString(oauthnonce)}\",");
            authorizationHeaderParams.Append($"oauth_signature_method=\"{Uri.EscapeDataString(OAuthSignatureMethod)}\",");
            authorizationHeaderParams.Append($"oauth_timestamp=\"{Uri.EscapeDataString(oauthtimestamp)}\",");
            authorizationHeaderParams.Append($"oauth_consumer_key=\"{Uri.EscapeDataString(consumerKey)}\",");
            if (!string.IsNullOrEmpty(token)) authorizationHeaderParams.Append($"oauth_token=\"{Uri.EscapeDataString(token)}\",");
            authorizationHeaderParams.Append($"oauth_signature=\"{Uri.EscapeDataString(oauthsignature)}\",");
            authorizationHeaderParams.Append($"oauth_version=\"{Uri.EscapeDataString(OAuthVersion)}\"");

            // Execute the request
            var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("OAuth", authorizationHeaderParams.ToString());
            httpClient.DefaultRequestHeaders.ExpectContinue = false;
            var json = await httpClient.GetStringAsync(completeUrl);
            return JsonConvert.DeserializeObject<T>(json);
        }

        private static string EncodeCharacters(string data)
        {
            //as per OAuth Core 1.0 Characters in the unreserved character set MUST NOT be encoded
            //unreserved = ALPHA, DIGIT, '-', '.', '_', '~'
            if (data.Contains("!"))
                data = data.Replace("!", "%21");
            if (data.Contains("'"))
                data = data.Replace("'", "%27");
            if (data.Contains("("))
                data = data.Replace("(", "%28");
            if (data.Contains(")"))
                data = data.Replace(")", "%29");
            if (data.Contains("*"))
                data = data.Replace("*", "%2A");
            if (data.Contains(","))
                data = data.Replace(",", "%2C");

            return data;
        }
    }
}
