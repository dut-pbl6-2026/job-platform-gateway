namespace Gateway.Api.Auth;

/// <summary>
/// Reads the instant after which previously issued access tokens for a user must be rejected.
/// Entries are written by auth-svc (deactivation) into the shared cache.
/// </summary>
public interface ITokenRevocationStore
{
    Task<DateTimeOffset?> GetRevokedAfterAsync(Guid userId, CancellationToken ct = default);
}
