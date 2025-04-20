using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace Infoware.AWS.Cognito.Authorizer.ApiGatewayAuthorizer;

public class ApiGatewayAuthenticationHandler<TOptions>(
    IOptionsMonitor<TOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    ISystemClock clock) : 
    AuthenticationHandler<TOptions>(options, logger, encoder, clock) where TOptions : AuthenticationSchemeOptions, new()
{
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
            var claimsIdentity = new ClaimsIdentity(Context.User.Claims, Scheme.Name);
            var principal = new ClaimsPrincipal(claimsIdentity);
            return Task.FromResult(
                AuthenticateResult.Success(
                    new AuthenticationTicket(principal, ApiGatewayJWTAuthorizerDefaults.AuthenticationScheme)));
        }
        catch (Exception exception)
        {
            return Task.FromResult(AuthenticateResult.Fail(exception));
        }
    }
}