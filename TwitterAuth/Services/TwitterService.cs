using Newtonsoft.Json;
using PCLCrypto;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using TwitterAuth.Authentication;

namespace TwitterAuth.Services
{
    public class TwitterService
    {
        public TwitterService(string oauthConsumerKey, string oauthConsumerSecret)
        {
            OauthConsumerKey = oauthConsumerKey;
            OauthConsumerSecret = oauthConsumerSecret;
        }

        public string OauthConsumerKey { get; }
        public string OauthConsumerSecret { get; }

        public async Task<string> GetEmailAsync(TwitterOAuthToken token)
        {
            string url = "https://api.twitter.com/1.1/account/verify_credentials.json";
            string oauthsignaturemethod = "HMAC-SHA1";
            string oauthversion = "1.0";
            string oauthnonce = Convert.ToBase64String(Encoding.UTF8.GetBytes(DateTime.Now.Ticks.ToString()));

            TimeSpan ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            string oauthtimestamp = Convert.ToInt64(ts.TotalSeconds).ToString();

            SortedDictionary<string, string> basestringParameters = new SortedDictionary<string, string>();
            basestringParameters.Add("include_email", "true");
            basestringParameters.Add("oauth_version", "1.0");
            basestringParameters.Add("oauth_consumer_key", OauthConsumerKey);
            basestringParameters.Add("oauth_nonce", oauthnonce);
            basestringParameters.Add("oauth_signature_method", "HMAC-SHA1");
            basestringParameters.Add("oauth_timestamp", oauthtimestamp);
            basestringParameters.Add("oauth_token", token.Token);

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
            string signingKey = EncodeCharacters(Uri.EscapeDataString(OauthConsumerSecret)) + "&" +
            EncodeCharacters(Uri.EscapeDataString(token.TokenSecret));

            //Sign the request
            var algorithm = WinRTCrypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha1);
            var hasher = algorithm.CreateHash(Encoding.UTF8.GetBytes(signingKey));
            hasher.Append(Encoding.UTF8.GetBytes(finalBaseString));
            string oauthsignature = Convert.ToBase64String(hasher.GetValueAndReset());

            //authorization header
            StringBuilder authorizationHeaderParams = new StringBuilder();
            authorizationHeaderParams.Append("oauth_nonce=" + "\"" + Uri.EscapeDataString(oauthnonce) + "\",");
            authorizationHeaderParams.Append("oauth_signature_method=" + "\"" + Uri.EscapeDataString(oauthsignaturemethod) + "\",");
            authorizationHeaderParams.Append("oauth_timestamp=" + "\"" + Uri.EscapeDataString(oauthtimestamp) + "\",");
            authorizationHeaderParams.Append("oauth_consumer_key=" + "\"" + Uri.EscapeDataString(OauthConsumerKey) + "\",");
            if (!string.IsNullOrEmpty(token.Token)) authorizationHeaderParams.Append("oauth_token=" + "\"" + Uri.EscapeDataString(token.Token) + "\",");
            authorizationHeaderParams.Append("oauth_signature=" + "\"" + Uri.EscapeDataString(oauthsignature) + "\",");
            authorizationHeaderParams.Append("oauth_version=" + "\"" + Uri.EscapeDataString(oauthversion) + "\"");

            var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("OAuth", authorizationHeaderParams.ToString());
            httpClient.DefaultRequestHeaders.ExpectContinue = false;
            var json = await httpClient.GetStringAsync(url + "?include_email=true");
            var email = JsonConvert.DeserializeObject<TwitterEmail>(json);

            return email.Email;
        }

        private string EncodeCharacters(string data)
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
