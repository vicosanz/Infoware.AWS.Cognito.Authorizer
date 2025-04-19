namespace Infoware.AWS.Cognito.Authorizer;

public record CognitoData
{
    public string? UserId { get; set; }
    public string? UserName { get; set; }
    public List<string> Groups { get; set; } = [];
    public string? ClientId { get; set; }
    public string? Email { get; set; }

    public Guid UserIdGuid() => Guid.Parse(UserId ?? Guid.Empty.ToString());
}