using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace Infoware.AWS.Cognito.ApiGatewayAuthorizer;

public class ApiGatewayAuthorizerTestHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public ApiGatewayAuthorizerTestHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
        : base(options, logger, encoder, clock)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var claims = new[]
        {
        new Claim(ApiGatewayAuthorizerClaims.UserName, "vicosanz"),
        new Claim(ApiGatewayAuthorizerClaims.Groups, "admin"),
        new Claim(ApiGatewayAuthorizerClaims.Email, "vicosanz@gmail.com"),
        new Claim(ApiGatewayAuthorizerClaims.UserId, "269e8f1d-be5b-49a9-9709-954c8e0068db"),
    };
        var identity = new ClaimsIdentity(claims, "Test");
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, "Test");

        var result = AuthenticateResult.Success(ticket);

        return Task.FromResult(result);
    }
}
