using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace Infoware.AWS.Cognito.Authorizer.ApiGatewayAuthorizer;

public class ApiGatewayJWTAuthenticationHandler(
    IOptionsMonitor<ApiGatewayJWTAuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    ISystemClock clock) : ApiGatewayAuthenticationHandler<ApiGatewayJWTAuthenticationSchemeOptions>(options, logger, encoder, clock)
{
    private static readonly string InvalidAuthenticationRequestMessage = "Invalid authentication request";
    private const string AuthorizationBearerKey = "Bearer";
    private const string AuthorizationHeaderKey = "Authorization";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        try
        {
            string? token = null;

            if (Options.RequireToken)
            {
                Logger.LogInformation("Validating Bearer token presence");
                token = GetToken();
                Logger.LogInformation("Token found: {token}", token);
                if (string.IsNullOrWhiteSpace(token))
                {
                    return AuthenticateResult.Fail(InvalidAuthenticationRequestMessage);
                }
            }

            var result = await base.HandleAuthenticateAsync();
            if (result.Succeeded)
            {
                return AuthenticateResult.Success(new AuthenticationTicket(Context.User, null, ApiGatewayJWTAuthorizerDefaults.AuthenticationScheme));
            }

            if (string.IsNullOrWhiteSpace(token) || !Options.ExtractClaimsFromToken)
            {
                return AuthenticateResult.Fail(InvalidAuthenticationRequestMessage);
            }

            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(token);
            var principal = new ClaimsPrincipal(new ClaimsIdentity(jwtSecurityToken.Claims, Scheme.Name));

            return AuthenticateResult.Success(new AuthenticationTicket(principal, null, ApiGatewayJWTAuthorizerDefaults.AuthenticationScheme));
        }
        catch (Exception exception)
        {
            return AuthenticateResult.Fail(exception);
        }
    }

    private string? GetToken()
    {
        var token = Context.Request.Headers[AuthorizationHeaderKey].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(token)) return null;

        if (token.StartsWith(AuthorizationBearerKey, StringComparison.OrdinalIgnoreCase))
        {
            token = token[AuthorizationBearerKey.Length..].Trim();
        }
        return token;
    }
}