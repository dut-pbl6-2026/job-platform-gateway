using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Gateway.Api.Auth;

/// <summary>
/// Checks that signature validation does not already cover: every accepted token names its signing key
/// (kid) and identifies its user (sub).
/// </summary>
public static class JwtClaimChecks
{
    public static bool HasKidAndSubject(SecurityToken? token, ClaimsPrincipal? principal)
    {
        if (token is not JsonWebToken jwt || string.IsNullOrEmpty(jwt.Kid))
            return false;
        var subject = principal?.FindFirst(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Sub)?.Value
                      ?? principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        return !string.IsNullOrWhiteSpace(subject);
    }
}
