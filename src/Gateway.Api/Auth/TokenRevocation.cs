using System.Globalization;
using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Gateway.Api.Auth;

/// <summary>
/// Decides whether a validated access token was issued before its user's revocation instant.
/// Mirrors auth-svc's check so both services reject the same tokens.
/// </summary>
public static class TokenRevocation
{
    /// <summary>
    /// Returns true when the token must be rejected. Store errors fail open (false) with a logged
    /// warning: signature and lifetime were already validated by the JWT handler.
    /// </summary>
    public static async Task<bool> IsRevokedAsync(
        ClaimsPrincipal? principal,
        ITokenRevocationStore store,
        ILogger logger,
        CancellationToken ct = default)
    {
        var subject = principal?.FindFirstValue(ClaimTypes.NameIdentifier)
                      ?? principal?.FindFirstValue(JwtRegisteredClaimNames.Sub);
        if (!Guid.TryParse(subject, out var userId))
            return false;

        var issuedAt = ReadIssuedAt(principal);
        try
        {
            var revokedAfter = await store.GetRevokedAfterAsync(userId, ct);
            if (!IsRevoked(issuedAt, revokedAfter))
                return false;

            logger.LogWarning(
                "Rejected revoked access token for user {UserId} (iat={IssuedAt}, revokedAfter={RevokedAfter})",
                userId,
                issuedAt,
                revokedAfter!.Value.ToUnixTimeSeconds());
            return true;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Token revocation check failed for user {UserId}", userId);
            return false;
        }
    }

    /// <summary>A token is revoked when it was issued at or before the revocation instant.</summary>
    public static bool IsRevoked(long issuedAtSeconds, DateTimeOffset? revokedAfter) =>
        revokedAfter is not null && issuedAtSeconds <= revokedAfter.Value.ToUnixTimeSeconds();

    /// <summary>Reads the iat claim in unix seconds. A missing or malformed iat is treated as 0.</summary>
    public static long ReadIssuedAt(ClaimsPrincipal? principal)
    {
        var raw = principal?.FindFirst(JwtRegisteredClaimNames.Iat)?.Value;
        return long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var issuedAt)
            ? issuedAt
            : 0;
    }
}
