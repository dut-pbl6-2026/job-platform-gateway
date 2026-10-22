namespace Gateway.Api.TokenRevocation;

/// <summary>
/// Used when no revocation backend is configured (local dev / tests): token
/// signature and lifetime are still enforced, but revoked tokens cannot be detected.
/// </summary>
public sealed class NoopTokenRevocationStore : ITokenRevocationStore
{
    public Task<DateTimeOffset?> GetRevokedAfterAsync(Guid userId, CancellationToken ct = default) =>
        Task.FromResult<DateTimeOffset?>(null);
}
