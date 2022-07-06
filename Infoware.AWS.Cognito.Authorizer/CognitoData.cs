using Infoware.SensitiveDataLogger.Attributes;
using System.Security.Claims;

namespace Infoware.AWS.Cognito.Authorizer
{
    public class CognitoData
    {
        public string? UserId { get; set; }
        public string? UserName { get; set; }
        public List<string> Groups { get; set; } = new List<string>();
        public string? ClientId { get; set; }
        [SensitiveData]
        public string? AccessToken { get; set; }
        public string? Email { get; set; }
        [SensitiveData]
        public string? IdToken { get; set; }

        public Guid UserIdGuid() => Guid.Parse(UserId ?? Guid.Empty.ToString());
    }
}