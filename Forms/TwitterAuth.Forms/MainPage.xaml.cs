using System;
using TwitterAuth.Authentication;
using TwitterAuth.Services;
using Xamarin.Auth;
using Xamarin.Auth.Presenters;
using Xamarin.Forms;

namespace TwitterAuth.Forms
{
    public partial class MainPage : ContentPage, ITwitterAuthenticationDelegate
    {
        private TwitterAuthenticator _auth;

        public MainPage()
        {
            InitializeComponent();
        }

        protected override void OnAppearing()
        {
            LoginButton.Clicked += OnTwitterLoginButtonClicked;
        }

        private void OnTwitterLoginButtonClicked(object sender, EventArgs e)
        {
            _auth = new TwitterAuthenticator(Configuration.ClientId, Configuration.ClientSecret, this);
            var authenticator = _auth.GetAuthenticator();
            var presenter = new OAuthLoginPresenter();
            presenter.Login(authenticator);
        }

        public async void OnAuthenticationCompleted(TwitterOAuthToken token)
        {
            // Retrieve the user's email address
            var twitterService = new TwitterService(Configuration.ClientId, Configuration.ClientSecret);
            var email = await twitterService.GetEmailAsync(token);

            // Display it on the UI
            LoginButton.Text = $"Connected with {email}";

            _auth = null;
        }

        public void OnAuthenticationCanceled()
        {
            DisplayAlert("Authentication canceled", "You didn't completed the authentication process", "OK");
        }

        public void OnAuthenticationFailed(string message, Exception exception)
        {
            DisplayAlert(message, exception.ToString(), "OK");
        }
    }
}
