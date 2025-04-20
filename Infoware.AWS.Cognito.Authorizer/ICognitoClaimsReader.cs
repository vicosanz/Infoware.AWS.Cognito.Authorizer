namespace Infoware.AWS.Cognito.Authorizer;

public interface ICognitoClaimsReader
{
    Task<CognitoData?> GetCognitoDataAsync();
}