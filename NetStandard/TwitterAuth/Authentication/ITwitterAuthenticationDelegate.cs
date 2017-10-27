using System;

namespace TwitterAuth.Authentication
{
    public interface ITwitterAuthenticationDelegate
    {
        void OnAuthenticationCompleted(TwitterOAuthToken token);
        void OnAuthenticationFailed(string message, Exception exception);
        void OnAuthenticationCanceled();
    }
}
