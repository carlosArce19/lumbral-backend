package app.lumbral.backend.auth.service;

import app.lumbral.backend.auth.model.MembershipRole;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JwtServiceTest {

    private static final String TEST_SECRET =
            "test-secret-that-is-at-least-32-bytes-long!!";

    private final JwtService service = new JwtService(
            TEST_SECRET, Duration.ofMinutes(15), Duration.ofMinutes(5));

    @Test
    void generateAndParseAccessToken() {
        UUID userId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        MembershipRole role = MembershipRole.ADMIN;
        UUID membershipId = UUID.randomUUID();

        String token = service.generateAccessToken(userId, tenantId, role, membershipId);
        Claims claims = service.parseAndValidate(token);

        assertThat(service.getUserId(claims)).isEqualTo(userId);
        assertThat(service.getTenantId(claims)).isEqualTo(tenantId);
        assertThat(service.getRole(claims)).isEqualTo(role);
        assertThat(service.getMembershipId(claims)).isEqualTo(membershipId);
        assertThat(service.getTokenType(claims)).isEqualTo(TokenType.ACCESS);
    }

    @Test
    void generateAndParsePreAuthToken() {
        UUID userId = UUID.randomUUID();

        String token = service.generatePreAuthToken(userId);
        Claims claims = service.parseAndValidate(token);

        assertThat(service.getUserId(claims)).isEqualTo(userId);
        assertThat(service.getTokenType(claims)).isEqualTo(TokenType.PRE_AUTH);
    }

    @Test
    void accessTokenContainsAllClaims() {
        UUID userId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        UUID membershipId = UUID.randomUUID();

        String token = service.generateAccessToken(
                userId, tenantId, MembershipRole.STAFF, membershipId);
        Claims claims = service.parseAndValidate(token);

        assertThat(claims.getSubject()).isEqualTo(userId.toString());
        assertThat(claims.get("tenantId", String.class)).isEqualTo(tenantId.toString());
        assertThat(claims.get("role", String.class)).isEqualTo("STAFF");
        assertThat(claims.get("membershipId", String.class)).isEqualTo(membershipId.toString());
        assertThat(claims.get("type", String.class)).isEqualTo("ACCESS");
        assertThat(claims.getIssuedAt()).isNotNull();
        assertThat(claims.getExpiration()).isNotNull();
    }

    @Test
    void preAuthTokenHasNoTenantId() {
        UUID userId = UUID.randomUUID();
        String token = service.generatePreAuthToken(userId);
        Claims claims = service.parseAndValidate(token);

        assertThrows(InvalidTokenException.class, () -> service.getTenantId(claims));
    }

    @Test
    void expiredTokenThrows() {
        JwtService shortLived = new JwtService(
                TEST_SECRET, Duration.ofSeconds(-1), Duration.ofSeconds(-1));
        String token = shortLived.generateAccessToken(
                UUID.randomUUID(), UUID.randomUUID(),
                MembershipRole.ADMIN, UUID.randomUUID());

        assertThrows(InvalidTokenException.class, () -> service.parseAndValidate(token));
    }

    @Test
    void tamperedTokenThrows() {
        String token = service.generateAccessToken(
                UUID.randomUUID(), UUID.randomUUID(),
                MembershipRole.ADMIN, UUID.randomUUID());
        String tampered = token.substring(0, token.length() - 5) + "XXXXX";

        assertThrows(InvalidTokenException.class, () -> service.parseAndValidate(tampered));
    }

    @Test
    void wrongSecretThrows() {
        String token = service.generateAccessToken(
                UUID.randomUUID(), UUID.randomUUID(),
                MembershipRole.ADMIN, UUID.randomUUID());

        JwtService otherService = new JwtService(
                "different-secret-that-is-also-32-bytes-long!!",
                Duration.ofMinutes(15), Duration.ofMinutes(5));

        assertThrows(InvalidTokenException.class, () -> otherService.parseAndValidate(token));
    }
}
