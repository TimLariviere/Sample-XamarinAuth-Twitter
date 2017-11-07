using System;
using Xamarin.Auth;

namespace TwitterAuth.Authentication
{
    public class TwitterAuthenticator
    {
        private const string AccessTokenUrl = "https://api.twitter.com/oauth/access_token";
        private const string AuthorizeUrl = "https://api.twitter.com/oauth/authorize";
        private const string RequestTokenUrl = "https://api.twitter.com/oauth/request_token";
        private const string RedirectUrl = "https://mobile.twitter.com/home";
        private const bool IsUsingNativeUI = false;

        private OAuth1Authenticator _auth;
        private ITwitterAuthenticationDelegate _authenticationDelegate;

        public TwitterAuthenticator(string clientId, string clientSecret, ITwitterAuthenticationDelegate authenticationDelegate)
        {
            _authenticationDelegate = authenticationDelegate;

            _auth = new OAuth1Authenticator(clientId, clientSecret,
                                            new Uri(RequestTokenUrl),
                                            new Uri(AuthorizeUrl),
                                            new Uri(AccessTokenUrl),
                                            new Uri(RedirectUrl),
                                            null, IsUsingNativeUI);

            _auth.Completed += OnAuthenticationCompleted;
            _auth.Error += OnAuthenticationFailed;
        }

        public OAuth1Authenticator GetAuthenticator()
        {
            return _auth;
        }

        private void OnAuthenticationCompleted(object sender, AuthenticatorCompletedEventArgs e)
        {
            if (e.IsAuthenticated)
            {
                var token = new TwitterOAuthToken
                {
                    Token = e.Account.Properties["oauth_token"],
                    TokenSecret = e.Account.Properties["oauth_token_secret"]
                };
                _authenticationDelegate.OnAuthenticationCompleted(token);
            }
            else
            {
                _authenticationDelegate.OnAuthenticationCanceled();
            }
        }

        private void OnAuthenticationFailed(object sender, AuthenticatorErrorEventArgs e)
        {
            _authenticationDelegate.OnAuthenticationFailed(e.Message, e.Exception);
        }
    }
}
