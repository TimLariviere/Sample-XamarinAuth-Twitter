using System.Collections.Generic;
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
            const string url = "https://api.twitter.com/1.1/account/verify_credentials.json";

            var parameters = new SortedDictionary<string, string>
            {
                { "include_email", "true" }
            };

            var result = await TwitterHelper.GetAsync<TwitterEmail>(OauthConsumerKey, OauthConsumerSecret, token.Token, token.TokenSecret, url, parameters);
            return result.Email;
        }
    }
}
