using Gateway.Api.Auth;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;

namespace Gateway.Api.Tests;

/// <summary>
/// Read side of the revocation store. The cached value is unix seconds written by auth-svc; a value
/// that does not parse must read as "not revoked" rather than throw.
/// </summary>
public class TokenRevocationStoreTests
{
    private static readonly Guid UserId = Guid.Parse("11111111-2222-3333-4444-555555555555");

    private static IDistributedCache NewCache() =>
        new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

    [Fact]
    public async Task GetRevokedAfter_ReadsUnixSecondsWrittenByAuthService()
    {
        var cache = NewCache();
        await cache.SetStringAsync(TokenRevocationStore.KeyFor(UserId), "1767225600");
        var store = new TokenRevocationStore(cache);

        var revokedAfter = await store.GetRevokedAfterAsync(UserId);

        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1767225600), revokedAfter);
    }

    [Fact]
    public async Task GetRevokedAfter_NoEntry_ReturnsNull()
    {
        var store = new TokenRevocationStore(NewCache());

        Assert.Null(await store.GetRevokedAfterAsync(UserId));
    }

    [Theory]
    [InlineData("not-a-number")]
    [InlineData("")]
    [InlineData("2026-01-01T00:00:00Z")]
    public async Task GetRevokedAfter_MalformedValue_ReturnsNullInsteadOfThrowing(string raw)
    {
        var cache = NewCache();
        await cache.SetStringAsync(TokenRevocationStore.KeyFor(UserId), raw);
        var store = new TokenRevocationStore(cache);

        Assert.Null(await store.GetRevokedAfterAsync(UserId));
    }
}
