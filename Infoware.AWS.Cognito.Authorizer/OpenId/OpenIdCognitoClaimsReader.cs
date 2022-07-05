using Infoware.AWS.Cognito.Authorizer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Infoware.AWS.Cognito.Authorizer.OpenId
{
    public class OpenIdCognitoClaimsReader : ICognitoClaimsReader
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        private CognitoData? _openIdData;

        public OpenIdCognitoClaimsReader(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task<CognitoData> GetOpenIdDataAsync()
        {
            if (_openIdData == null)
            {
                var user = _httpContextAccessor.HttpContext.User;
                if (user?.Identity?.IsAuthenticated ?? false)
                {
                    var userId = user.FindFirst(CognitoClaims.UserId);
                    var userName = user.FindFirst(CognitoClaims.UserName);
                    var userName2 = user.FindFirst(CognitoClaims.UserName2);
                    var groups = user.FindAll(CognitoClaims.Groups);
                    var clientId = user.FindFirst(CognitoClaims.ClientId);
                    var email = user.FindFirst(CognitoClaims.Email);
                    var accessToken = await _httpContextAccessor.HttpContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);
                    var idToken = await _httpContextAccessor.HttpContext.GetTokenAsync(OpenIdConnectParameterNames.IdToken);
                    string? userNameFinal = !string.IsNullOrWhiteSpace(userName?.Value) ? userName?.Value : userName2?.Value;
                    _openIdData = new CognitoData()
                    {
                        UserId = userId?.Value,
                        UserName = userNameFinal,
                        Email = email?.Value,
                        ClientId = clientId?.Value,
                        Groups = groups.ToList().ConvertAll(x => x.Value),
                        AccessToken = accessToken,
                        IdToken = idToken,
                    };
                }
            }
            return _openIdData!;
        }
    }
}
