namespace Infoware.AWS.Cognito.Authorizer;

public interface ICognitoClaimsReader
{
    CognitoData? CognitoData { get; }
}