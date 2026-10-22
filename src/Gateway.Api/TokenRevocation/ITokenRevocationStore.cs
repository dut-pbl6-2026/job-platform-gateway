namespace Gateway.Api.TokenRevocation;

public interface ITokenRevocationStore
{
    Task<DateTimeOffset?> GetRevokedAfterAsync(Guid userId, CancellationToken ct = default);
}
