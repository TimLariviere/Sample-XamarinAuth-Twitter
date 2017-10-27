using System;
using TwitterAuth.Authentication;
using TwitterAuth.Services;
using UIKit;

namespace TwitterAuth.Native.iOS
{
    public partial class ViewController : UIViewController, ITwitterAuthenticationDelegate
    {
        public ViewController(IntPtr handle) : base(handle)
        {

        }

        public override void ViewDidLoad()
        {
            base.ViewDidLoad();

            LoginButton.TouchUpInside += OnTwitterLoginButtonClicked;
        }

        public override void DidReceiveMemoryWarning()
        {
            base.DidReceiveMemoryWarning();
        }

        private void OnTwitterLoginButtonClicked(object sender, EventArgs e)
        {
            var auth = new TwitterAuthenticator(Configuration.ClientId, Configuration.ClientSecret, this);
            var authenticator = auth.GetAuthenticator();
            var viewController = authenticator.GetUI();
            PresentViewController(viewController, true, null);
        }

        public async void OnAuthenticationCompleted(TwitterOAuthToken token)
        {
            DismissViewController(true, null);

            var twitterService = new TwitterService(Configuration.ClientId, Configuration.ClientSecret);
            var email = await twitterService.GetEmailAsync(token);

            LoginButton.SetTitle($"Connected with {email}", UIControlState.Normal);
        }

        public void OnAuthenticationFailed(string message, Exception exception)
        {
            DismissViewController(true, null);

            var alertController = new UIAlertController
            {
                Title = message,
                Message = exception?.ToString()
            };
            PresentViewController(alertController, true, null);
        }

        public void OnAuthenticationCanceled()
        {
            DismissViewController(true, null);

            var alertController = new UIAlertController
            {
                Title = "Authentication canceled",
                Message = "You didn't completed the authentication process"
            };
            PresentViewController(alertController, true, null);
        }
    }
}

