using Microsoft.AspNetCore.Authentication;

namespace Infoware.AWS.Cognito.Authorizer.ApiGatewayAuthorizer;

public static class ApiGatewayJWTAuthorizerExtensions
{
    public static AuthenticationBuilder AddApiGatewayJWTAuthorizerScheme(this AuthenticationBuilder builder)
    {
        return builder.AddApiGatewayJWTAuthorizerSchemeInternal(ApiGatewayJWTAuthorizerDefaults.AuthenticationScheme);
    }

    public static AuthenticationBuilder AddApiGatewayJWTAuthorizerScheme(this AuthenticationBuilder builder, string authenticationScheme)
    {
        return builder.AddApiGatewayJWTAuthorizerSchemeInternal(authenticationScheme);
    }

    public static AuthenticationBuilder AddApiGatewayJWTAuthorizerScheme(
        this AuthenticationBuilder builder,
        Action<ApiGatewayJWTAuthenticationSchemeOptions> configureOptions)
    {
        return builder.AddApiGatewayJWTAuthorizerSchemeInternal(ApiGatewayJWTAuthorizerDefaults.AuthenticationScheme, configureOptions);
    }

    public static AuthenticationBuilder AddApiGatewayAuthorizerScheme(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        Action<ApiGatewayJWTAuthenticationSchemeOptions> configureOptions)
    {
        return builder.AddApiGatewayJWTAuthorizerSchemeInternal(authenticationScheme, configureOptions);
    }

    private static AuthenticationBuilder AddApiGatewayJWTAuthorizerSchemeInternal(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        Action<ApiGatewayJWTAuthenticationSchemeOptions>? configureOptions = null)
    {
        return builder
            .AddScheme<ApiGatewayJWTAuthenticationSchemeOptions, ApiGatewayJWTAuthenticationHandler>(
                authenticationScheme,
                configureOptions);
    }
}
