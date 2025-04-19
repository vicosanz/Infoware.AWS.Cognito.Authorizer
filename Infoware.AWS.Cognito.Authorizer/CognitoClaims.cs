using System.Security.Claims;

namespace Infoware.AWS.Cognito.Authorizer;

public static class CognitoClaims
{
    public const string UserName = "username";
    public const string UserName2 = "cognito:username";
    public const string Groups = "cognito:groups";
    public const string ClientId = "client_id";
    public const string UserId = ClaimTypes.NameIdentifier;
    public const string Scopes = "scope";
    public const string PhoneNumber = "phone_number";
    public const string Email = ClaimTypes.Email;
}
