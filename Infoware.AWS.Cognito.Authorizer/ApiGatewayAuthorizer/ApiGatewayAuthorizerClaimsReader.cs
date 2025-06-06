﻿using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Infoware.AWS.Cognito.Authorizer.ApiGatewayAuthorizer;

public class ApiGatewayAuthorizerClaimsReader(
    IHttpContextAccessor httpContextAccessor, 
    ILogger<ApiGatewayAuthorizerClaimsReader> logger) : ICognitoClaimsReader
{
    private CognitoData? cognitoData = null;

    private CognitoData? GetOpenIdData()
    {
        if (httpContextAccessor?.HttpContext != null)
        {
            var user = httpContextAccessor.HttpContext.User;
            if (user?.Identity?.IsAuthenticated ?? false)
            {
                var userId = user.FindFirst(ApiGatewayAuthorizerClaims.UserId);
                var userName = user.FindFirst(ApiGatewayAuthorizerClaims.UserName);
                var groups = user.FindAll(ApiGatewayAuthorizerClaims.Groups);
                var email = user.FindFirst(ApiGatewayAuthorizerClaims.Email);
                List<string> listgroups = [];
                if (groups?.Any() ?? false)
                {
                    foreach(var group in groups)
                    {
                        listgroups.AddRange(group.Value.Split(','));
                    }
                }

                return new CognitoData()
                {
                    UserId = userId?.Value,
                    UserName = userName?.Value,
                    Email = email?.Value,
                    Groups = listgroups,
                };
            }
        }
        return null;
    }

    public Task<CognitoData?> GetCognitoDataAsync(CancellationToken cancellationToken)
    {
        if (cognitoData is null)
        {
            cognitoData = GetOpenIdData();
            if (cognitoData != null)
            {
                logger.LogInformation("User found: {@CognitoData}", cognitoData);
            }
        }
        return Task.FromResult(cognitoData);
    }
}
