using System.Security.Claims;
using Gateway.Api.Auth;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Gateway.Api.Tests;

public class TokenRevocationTests
{
    private static readonly Guid UserId = Guid.Parse("11111111-2222-3333-4444-555555555555");

    private static ClaimsPrincipal Principal(string? sub, long? iat, string subClaimType = JwtRegisteredClaimNames.Sub)
    {
        var claims = new List<Claim>();
        if (sub is not null)
            claims.Add(new Claim(subClaimType, sub));
        if (iat is not null)
            claims.Add(new Claim(JwtRegisteredClaimNames.Iat, iat.Value.ToString(), ClaimValueTypes.Integer64));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
    }

    private sealed class FakeStore(DateTimeOffset? revokedAfter, Exception? error = null) : ITokenRevocationStore
    {
        public Task<DateTimeOffset?> GetRevokedAfterAsync(Guid userId, CancellationToken ct = default) =>
            error is not null ? throw error : Task.FromResult(revokedAfter);
    }

    [Fact]
    public void IsRevoked_TokenIssuedBeforeRevocation_IsRevoked()
    {
        Assert.True(TokenRevocation.IsRevoked(1_000, DateTimeOffset.FromUnixTimeSeconds(2_000)));
    }

    [Fact]
    public void IsRevoked_TokenIssuedAtRevocationInstant_IsRevoked()
    {
        Assert.True(TokenRevocation.IsRevoked(2_000, DateTimeOffset.FromUnixTimeSeconds(2_000)));
    }

    [Fact]
    public void IsRevoked_TokenIssuedAfterRevocation_IsNotRevoked()
    {
        Assert.False(TokenRevocation.IsRevoked(2_001, DateTimeOffset.FromUnixTimeSeconds(2_000)));
    }

    [Fact]
    public void IsRevoked_NoRevocationEntry_IsNotRevoked()
    {
        Assert.False(TokenRevocation.IsRevoked(1, null));
    }

    [Fact]
    public void ReadIssuedAt_MissingIat_IsZero()
    {
        Assert.Equal(0, TokenRevocation.ReadIssuedAt(Principal(UserId.ToString(), iat: null)));
    }

    [Fact]
    public void ReadIssuedAt_MalformedIat_IsZero()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(JwtRegisteredClaimNames.Iat, "not-a-number")], "test"));

        Assert.Equal(0, TokenRevocation.ReadIssuedAt(principal));
    }

    [Fact]
    public void ReadIssuedAt_ReadsUnixSeconds()
    {
        Assert.Equal(1_700_000_000, TokenRevocation.ReadIssuedAt(Principal(UserId.ToString(), 1_700_000_000)));
    }

    [Fact]
    public async Task IsRevokedAsync_MissingIat_IsRevokedWhenEntryExists()
    {
        // Missing iat counts as 0, so any existing revocation entry rejects the token.
        var store = new FakeStore(DateTimeOffset.FromUnixTimeSeconds(1));

        var revoked = await TokenRevocation.IsRevokedAsync(
            Principal(UserId.ToString(), iat: null), store, NullLogger.Instance);

        Assert.True(revoked);
    }

    [Fact]
    public async Task IsRevokedAsync_NoSubjectClaim_IsNotCheckedAndNotRevoked()
    {
        var store = new FakeStore(DateTimeOffset.FromUnixTimeSeconds(1));

        var revoked = await TokenRevocation.IsRevokedAsync(
            Principal(sub: null, iat: 1_000), store, NullLogger.Instance);

        Assert.False(revoked);
    }

    [Fact]
    public async Task IsRevokedAsync_StoreThrows_FailsOpen()
    {
        var store = new FakeStore(null, new InvalidOperationException("redis down"));

        var revoked = await TokenRevocation.IsRevokedAsync(
            Principal(UserId.ToString(), iat: 1_000), store, NullLogger.Instance);

        Assert.False(revoked);
    }

    [Fact]
    public async Task IsRevokedAsync_SubjectFromNameIdentifier_IsUsed()
    {
        var store = new FakeStore(DateTimeOffset.FromUnixTimeSeconds(2_000));
        var principal = Principal(UserId.ToString(), iat: 1_000, subClaimType: ClaimTypes.NameIdentifier);

        Assert.True(await TokenRevocation.IsRevokedAsync(principal, store, NullLogger.Instance));
    }

    [Fact]
    public async Task IsRevokedAsync_NonGuidSubject_IsNotChecked()
    {
        var store = new FakeStore(DateTimeOffset.FromUnixTimeSeconds(2_000));

        var revoked = await TokenRevocation.IsRevokedAsync(
            Principal("user-abc", iat: 1_000), store, NullLogger.Instance);

        Assert.False(revoked);
    }

    [Fact]
    public void KeyFor_UsesSharedPrefixAndDashedGuid()
    {
        Assert.Equal(
            "job-platform:auth:revoked-after:11111111-2222-3333-4444-555555555555",
            TokenRevocationStore.KeyFor(UserId));
    }
}
