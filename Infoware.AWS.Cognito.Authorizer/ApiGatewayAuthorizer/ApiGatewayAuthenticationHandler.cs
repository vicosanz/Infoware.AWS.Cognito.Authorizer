using Infoware.AWS.Cognito.Authorizer.OpenId;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace Infoware.AWS.Cognito.Authorizer.ApiGatewayAuthorizer
{
    public class ApiGatewayAuthenticationHandler<TOptions> : AuthenticationHandler<TOptions>
        where TOptions : AuthenticationSchemeOptions, new()
    {
        public ApiGatewayAuthenticationHandler(
            IOptionsMonitor<TOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder)
            : base(options, logger, encoder)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            try
            {
                Logger.LogInformation("Checking claims");
                Logger.LogInformation("User {name}", Context.User.Identity?.Name);
                if (!Context.User.Claims.Any())
                {
                    return Task.FromResult(AuthenticateResult.Fail("Couldn't find the user authenticated by API Gateway"));
                }
                var userId = Context.User.FindFirst(CognitoClaims.UserId);
                var email = Context.User.FindFirst(CognitoClaims.Email);

                Logger.LogInformation("UserId {id}, Email {email}", userId?.Value, email?.Value);

                Logger.LogInformation("Found user already authenticated by API Gateway Authorizer");
                var claimsIdentity = new ClaimsIdentity(Context.User.Claims, Scheme.Name);
                var principal = new ClaimsPrincipal(claimsIdentity);
                return Task.FromResult(
                    AuthenticateResult.Success(
                        new AuthenticationTicket(principal, null, ApiGatewayJWTAuthorizerDefaults.AuthenticationScheme)));
            }
            catch (Exception exception)
            {
                return Task.FromResult(AuthenticateResult.Fail(exception));
            }
        }
    }
}