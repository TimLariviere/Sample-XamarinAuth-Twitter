using Android.App;
using Android.OS;
using Android.Widget;
using System;
using TwitterAuth.Authentication;
using TwitterAuth.Services;

namespace TwitterAuth.Native.Droid
{
    [Activity (Label = "TwitterAuth.Native.Android", MainLauncher = true, Icon = "@drawable/icon")]
	public class MainActivity : Activity, ITwitterAuthenticationDelegate
	{
        private TwitterAuthenticator _auth;

        protected override void OnCreate (Bundle bundle)
		{
			base.OnCreate (bundle);

			SetContentView (Resource.Layout.Main);

            var loginButton = FindViewById<Button>(Resource.Id.loginButton);
            loginButton.Click += OnTwitterLoginButtonClicked;
        }

        private void OnTwitterLoginButtonClicked(object sender, EventArgs e)
        {
            // Display the activity handling the authentication
            var authenticator = _auth.GetAuthenticator();
            var intent = authenticator.GetUI(this);
            StartActivity(intent);
        }

        public async void OnAuthenticationCompleted(TwitterOAuthToken token)
        {
            // Retrieve the user's email address
            var twitterService = new TwitterService(Configuration.ClientId, Configuration.ClientSecret);
            var email = await twitterService.GetEmailAsync(token);

            // Display it on the UI
            var loginButton = FindViewById<Button>(Resource.Id.loginButton);
            loginButton.Text = $"Connected with {email}";
        }

        public void OnAuthenticationCanceled()
        {
            new AlertDialog.Builder(this)
                           .SetTitle("Authentication canceled")
                           .SetMessage("You didn't completed the authentication process")
                           .Show();
        }

        public void OnAuthenticationFailed(string message, Exception exception)
        {
            new AlertDialog.Builder(this)
                           .SetTitle(message)
                           .SetMessage(exception?.ToString())
                           .Show();
        }
    }
}


