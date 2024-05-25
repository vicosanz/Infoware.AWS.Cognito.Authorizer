using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace Infoware.AWS.Cognito.Authorizer.ApiGatewayAuthorizer
{
    public class ApiGatewayJWTAuthenticationHandler : ApiGatewayAuthenticationHandler<ApiGatewayJWTAuthenticationSchemeOptions>
    {
        private static readonly string InvalidAuthenticationRequestMessage = "Invalid authentication request";

        public ApiGatewayJWTAuthenticationHandler(
            IOptionsMonitor<ApiGatewayJWTAuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

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
                var claimsIdentity = new ClaimsIdentity(jwtSecurityToken.Claims, Scheme.Name);
                var principal = new ClaimsPrincipal(claimsIdentity);

                return AuthenticateResult.Success(new AuthenticationTicket(principal, null, ApiGatewayJWTAuthorizerDefaults.AuthenticationScheme));
            }
            catch (Exception exception)
            {
                return AuthenticateResult.Fail(exception);
            }
        }

        private string? GetToken()
        {
            var authorizationHeader = Context.Request
                .Headers["Authorization"]
                .ToArray();
            if (authorizationHeader?.Any() != true)
            {
                return null;
            }
            var token = authorizationHeader.First();
            const string AuthorizationBearerKey = "Bearer";
            if (token != null && token.StartsWith(AuthorizationBearerKey, StringComparison.OrdinalIgnoreCase))
            {
                token = token[AuthorizationBearerKey.Length..].Trim();
            }
            return string.IsNullOrWhiteSpace(token)
                ? null
                : token;
        }
    }
}