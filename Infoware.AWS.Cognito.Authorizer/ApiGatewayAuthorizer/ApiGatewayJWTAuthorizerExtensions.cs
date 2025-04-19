using Microsoft.AspNetCore.Authentication;

namespace Infoware.AWS.Cognito.Authorizer.ApiGatewayAuthorizer;

public static class ApiGatewayJWTAuthorizerExtensions
{
    public static AuthenticationBuilder AddApiGatewayJWTAuthorizerScheme(this AuthenticationBuilder builder) => 
        builder.AddApiGatewayJWTAuthorizerSchemeInternal(ApiGatewayJWTAuthorizerDefaults.AuthenticationScheme);

    public static AuthenticationBuilder AddApiGatewayJWTAuthorizerScheme(this AuthenticationBuilder builder, string authenticationScheme) => 
        builder.AddApiGatewayJWTAuthorizerSchemeInternal(authenticationScheme);

    public static AuthenticationBuilder AddApiGatewayJWTAuthorizerScheme(
        this AuthenticationBuilder builder,
        Action<ApiGatewayJWTAuthenticationSchemeOptions> configureOptions) => 
        builder.AddApiGatewayJWTAuthorizerSchemeInternal(ApiGatewayJWTAuthorizerDefaults.AuthenticationScheme, configureOptions);

    public static AuthenticationBuilder AddApiGatewayAuthorizerScheme(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        Action<ApiGatewayJWTAuthenticationSchemeOptions> configureOptions) => 
        builder.AddApiGatewayJWTAuthorizerSchemeInternal(authenticationScheme, configureOptions);

    private static AuthenticationBuilder AddApiGatewayJWTAuthorizerSchemeInternal(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        Action<ApiGatewayJWTAuthenticationSchemeOptions>? configureOptions = null) => 
        builder.AddScheme<ApiGatewayJWTAuthenticationSchemeOptions, ApiGatewayJWTAuthenticationHandler>(
                authenticationScheme,
                configureOptions);
}
