package app.lumbral.backend.auth.service;

import app.lumbral.backend.auth.model.RefreshToken;
import app.lumbral.backend.auth.model.User;
import app.lumbral.backend.auth.model.UserStatus;
import app.lumbral.backend.auth.repository.RefreshTokenRepository;
import app.lumbral.backend.tenancy.model.Tenant;
import app.lumbral.backend.tenancy.model.TenantPlan;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository repository;

    private RefreshTokenService service;

    @BeforeEach
    void setUp() {
        service = new RefreshTokenService(repository, Duration.ofHours(14));
    }

    private User testUser() {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail("test@example.com");
        user.setPasswordHash("hash");
        user.setStatus(UserStatus.ACTIVE);
        return user;
    }

    private Tenant testTenant() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Test Tenant");
        tenant.setCode("test");
        tenant.setPlan(TenantPlan.BASIC);
        return tenant;
    }

    private String generateRawToken() {
        byte[] rawBytes = new byte[32];
        new SecureRandom().nextBytes(rawBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(rawBytes);
    }

    private String sha256Hex(byte[] bytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(bytes);
            StringBuilder sb = new StringBuilder(64);
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private RefreshToken buildToken(User user, Tenant tenant, String rawToken, boolean revoked) {
        byte[] rawBytes = Base64.getUrlDecoder().decode(rawToken);
        RefreshToken token = new RefreshToken();
        token.setId(UUID.randomUUID());
        token.setUser(user);
        token.setTenant(tenant);
        token.setTokenHash(sha256Hex(rawBytes));
        token.setExpiresAt(Instant.now().plus(Duration.ofHours(14)));
        if (revoked) {
            token.setRevokedAt(Instant.now().minus(Duration.ofMinutes(5)));
        }
        return token;
    }

    @Test
    void createStoresHashNotRawToken() {
        User user = testUser();
        Tenant tenant = testTenant();

        when(repository.save(any(RefreshToken.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        String rawToken = service.createRefreshToken(user, tenant);

        assertThat(rawToken).isNotBlank();

        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(repository).save(captor.capture());

        RefreshToken saved = captor.getValue();
        assertThat(saved.getTokenHash()).isNotEqualTo(rawToken);
        assertThat(saved.getTokenHash()).hasSize(64);
        assertThat(saved.getUser()).isEqualTo(user);
        assertThat(saved.getTenant()).isEqualTo(tenant);
        assertThat(saved.getExpiresAt()).isAfter(Instant.now());
    }

    @Test
    void rotateRevokesOldAndCreatesNew() {
        User user = testUser();
        Tenant tenant = testTenant();
        String rawToken = generateRawToken();
        byte[] rawBytes = Base64.getUrlDecoder().decode(rawToken);
        String hash = sha256Hex(rawBytes);

        RefreshToken oldToken = buildToken(user, tenant, rawToken, false);

        when(repository.findByTokenHash(hash)).thenReturn(Optional.of(oldToken));
        when(repository.save(any(RefreshToken.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        RefreshTokenService.RotationResult result = service.rotateRefreshToken(rawToken);

        assertThat(result.newRawToken()).isNotBlank();
        assertThat(result.newRawToken()).isNotEqualTo(rawToken);
        assertThat(oldToken.getRevokedAt()).isNotNull();

        verify(repository, times(2)).save(any(RefreshToken.class));
    }

    @Test
    void rotateWithRevokedTokenThrowsReuse() {
        User user = testUser();
        Tenant tenant = testTenant();
        String rawToken = generateRawToken();
        byte[] rawBytes = Base64.getUrlDecoder().decode(rawToken);
        String hash = sha256Hex(rawBytes);

        RefreshToken revokedToken = buildToken(user, tenant, rawToken, true);

        when(repository.findByTokenHash(hash)).thenReturn(Optional.of(revokedToken));

        assertThatThrownBy(() -> service.rotateRefreshToken(rawToken))
                .isInstanceOf(RefreshTokenReusedException.class);
    }

    @Test
    void rotateWithRevokedTokenRevokesFamily() {
        User user = testUser();
        Tenant tenant = testTenant();
        String rawToken = generateRawToken();
        byte[] rawBytes = Base64.getUrlDecoder().decode(rawToken);
        String hash = sha256Hex(rawBytes);

        RefreshToken revokedToken = buildToken(user, tenant, rawToken, true);

        when(repository.findByTokenHash(hash)).thenReturn(Optional.of(revokedToken));

        assertThatThrownBy(() -> service.rotateRefreshToken(rawToken))
                .isInstanceOf(RefreshTokenReusedException.class);

        verify(repository).revokeAllByUserIdAndTenantId(
                eq(user.getId()), eq(tenant.getId()), any(Instant.class));
    }

    @Test
    void rotateWithExpiredTokenThrows() {
        User user = testUser();
        Tenant tenant = testTenant();
        String rawToken = generateRawToken();
        byte[] rawBytes = Base64.getUrlDecoder().decode(rawToken);
        String hash = sha256Hex(rawBytes);

        RefreshToken expiredToken = new RefreshToken();
        expiredToken.setId(UUID.randomUUID());
        expiredToken.setUser(user);
        expiredToken.setTenant(tenant);
        expiredToken.setTokenHash(hash);
        expiredToken.setExpiresAt(Instant.now().minus(Duration.ofHours(1)));

        when(repository.findByTokenHash(hash)).thenReturn(Optional.of(expiredToken));

        assertThatThrownBy(() -> service.rotateRefreshToken(rawToken))
                .isInstanceOf(InvalidTokenException.class);
    }
}
