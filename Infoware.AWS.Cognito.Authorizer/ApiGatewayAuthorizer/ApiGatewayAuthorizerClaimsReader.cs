using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Infoware.AWS.Cognito.Authorizer.ApiGatewayAuthorizer
{
    public class ApiGatewayAuthorizerClaimsReader : ICognitoClaimsReader
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        private CognitoData? _openIdData;

        public ApiGatewayAuthorizerClaimsReader(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task<CognitoData> GetOpenIdDataAsync()
        {
            if (_openIdData == null && _httpContextAccessor?.HttpContext != null)
            {
                var user = _httpContextAccessor.HttpContext.User;
                if (user?.Identity?.IsAuthenticated ?? false)
                {
                    var userId = user.FindFirst(ApiGatewayAuthorizerClaims.UserId);
                    var userName = user.FindFirst(ApiGatewayAuthorizerClaims.UserName);
                    var groups = user.FindAll(ApiGatewayAuthorizerClaims.Groups);
                    var email = user.FindFirst(ApiGatewayAuthorizerClaims.Email);
                    var accessToken = await _httpContextAccessor.HttpContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);
                    var idToken = await _httpContextAccessor.HttpContext.GetTokenAsync(OpenIdConnectParameterNames.IdToken);
                    List<string> listgroups = new();
                    if (groups?.Any() ?? false)
                    {
                        foreach(var group in groups)
                        {
                            listgroups.AddRange(group.Value.Split(',').ToList());
                        }
                    }
                    _openIdData = new CognitoData()
                    {
                        UserId = userId?.Value,
                        UserName = userName?.Value,
                        Email = email?.Value,
                        Groups = listgroups,
                        AccessToken = accessToken,
                        IdToken = idToken
                    };
                }
            }
            return _openIdData!;
        }
    }
}
