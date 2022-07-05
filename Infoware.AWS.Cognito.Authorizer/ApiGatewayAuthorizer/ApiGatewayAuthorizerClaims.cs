using System.Security.Claims;

namespace Infoware.AWS.Cognito.Authorizer.ApiGatewayAuthorizer
{
    public static class ApiGatewayAuthorizerClaims
    {
        public const string UserName = "cognito:username";
        public const string Groups = "cognito:groups";
        public const string ClientId = "client_id";
        public const string UserId = "sub";
        public const string Scopes = "scope";
        public const string PhoneNumber = "phone_number";
        public const string Email = "email";
    }
}
