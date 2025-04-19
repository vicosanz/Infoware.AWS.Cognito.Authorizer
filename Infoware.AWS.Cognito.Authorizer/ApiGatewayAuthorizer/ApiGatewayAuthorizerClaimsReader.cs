using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Infoware.AWS.Cognito.Authorizer.ApiGatewayAuthorizer;

public class ApiGatewayAuthorizerClaimsReader : ICognitoClaimsReader
{
    public CognitoData? CognitoData { get; }

    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<ApiGatewayAuthorizerClaimsReader> _logger;

    public ApiGatewayAuthorizerClaimsReader(IHttpContextAccessor httpContextAccessor, ILogger<ApiGatewayAuthorizerClaimsReader> logger)
    {
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
        CognitoData = GetOpenIdData();
        if (CognitoData != null)
        {
            _logger.LogInformation("User found: {@CognitoData}", CognitoData);
        }
    }

    private CognitoData? GetOpenIdData()
    {
        if (_httpContextAccessor?.HttpContext != null)
        {
            var user = _httpContextAccessor.HttpContext.User;
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
}
