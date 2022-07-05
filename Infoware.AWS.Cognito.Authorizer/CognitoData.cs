using Infoware.SensitiveDataLogger.Attributes;
using System.Security.Claims;

namespace Infoware.AWS.Cognito.Authorizer
{
    public class CognitoData
    {
        public string? UserId { get; internal set; }
        public string? UserName { get; internal set; }
        public List<string> Groups { get; internal set; } = new List<string>();
        public string? ClientId { get; internal set; }
        [SensitiveData]
        public string? AccessToken { get; internal set; }
        public string? Email { get; internal set; }
        [SensitiveData]
        public string? IdToken { get; internal set; }

        public Guid UserIdGuid() => Guid.Parse(UserId ?? Guid.Empty.ToString());
    }
}