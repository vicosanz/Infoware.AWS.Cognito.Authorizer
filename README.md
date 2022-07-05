# Infoware.AWS.Cognito.Authorizer
Handle [Authorize] for Controllers that need to enable security through claims.
If you publish your api as AWS lambda in a API Gateway protected with Cognito Authorizer and you need secure your controllers already injected throw API Gateway to Lambda use this package.
In otherwise if you consume Authorization using Cognito with this package you can read cognito claims.

### Get it!
[![NuGet Badge](https://buildstats.info/nuget/Infoware.AWS.Cognito.Authorizer)](https://www.nuget.org/packages/Infoware.AWS.Cognito.Authorizer/)

### How to use it
#### Using Authorization with AWS Lambda + API Gateway + Authorizer Cognito
- Inject via Dependency Injection to ApiGatewayAuthorizerClaimsReader
- Add Authentication scheme AddApiGatewayJWTAuthorizerScheme

```csharp
        services.AddAnotherService();

        services.AddHttpContextAccessor();
        services.AddScoped<ICognitoClaimsReader, ApiGatewayAuthorizerClaimsReader>();

        builder.Services.AddAuthentication(ApiGatewayJWTAuthorizerDefaults.AuthenticationScheme)
            .AddApiGatewayJWTAuthorizerScheme(options =>
            {
                options.RequireToken = true;
                options.ExtractClaimsFromToken = builder.Environment.IsDevelopment(); //In develop mode if you have a token you can decrypt and read his information
            });
```

#### Using Authorization with OpenIdConnect + Cognito
- Inject via Dependency Injection to OpenIdCognitoClaimsReader
- Add Authentication scheme OpenIdConnect

```csharp
        services.AddAnotherService();

        services.AddHttpContextAccessor();
        services.AddScoped<ICognitoClaimsReader, OpenIdCognitoClaimsReader>();

        builder.Services.AddAuthentication(options =>
        {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = "cognito";
        })
        .AddCookie(options =>
        {
            options.ExpireTimeSpan = TimeSpan.FromMinutes(58);
            options.SlidingExpiration = !authOptions!.UseTokenLifetime;
            options.Cookie.Name = "cookieauth";
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        })
        .AddOpenIdConnect("cognito", options =>
        {
            options.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;
            options.NonceCookie.SameSite = SameSiteMode.Lax;
            options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
            options.CorrelationCookie.SameSite = SameSiteMode.Lax;

            options.ClaimsIssuer = "cognito";
            options.ResponseType = authOptions!.ResponseType;
            options.MetadataAddress = authOptions.MetadataAddress;
            options.ClientId = authOptions.ClientId;
            options.ClientSecret = authOptions.ClientSecret;
            options.Scope.Add("email");
            options.Scope.Add("openid");
            options.Scope.Add("profile");
            options.GetClaimsFromUserInfoEndpoint = true;
            options.SaveTokens = authOptions.SaveTokens;
            options.UseTokenLifetime = authOptions.UseTokenLifetime;
            ...


```


## Buy me a coofee
If you want, buy me a coofee :coffee: https://www.paypal.com/paypalme/vicosanzdev?locale.x=es_XC

