package app.lumbral.backend.auth.service;

import app.lumbral.backend.auth.model.RefreshToken;
import app.lumbral.backend.auth.model.User;
import app.lumbral.backend.auth.model.UserStatus;
import app.lumbral.backend.auth.repository.RefreshTokenRepository;
import app.lumbral.backend.auth.repository.UserRepository;
import app.lumbral.backend.tenancy.model.Tenant;
import app.lumbral.backend.tenancy.model.TenantPlan;
import app.lumbral.backend.tenancy.repository.TenantRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.context.ImportTestcontainers;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.PostgreSQLContainer;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@ImportTestcontainers
class RefreshTokenServiceIT {

    @ServiceConnection
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TenantRepository tenantRepository;

    private User testUser;
    private Tenant testTenant;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setEmail("it-" + UUID.randomUUID() + "@example.com");
        testUser.setPasswordHash("hash");
        testUser.setStatus(UserStatus.ACTIVE);
        testUser = userRepository.saveAndFlush(testUser);

        testTenant = new Tenant();
        testTenant.setName("IT Tenant");
        testTenant.setCode("it-" + UUID.randomUUID().toString().substring(0, 8));
        testTenant.setPlan(TenantPlan.BASIC);
        testTenant = tenantRepository.saveAndFlush(testTenant);
    }

    @Test
    void createAndLookupByHash() {
        String rawToken = refreshTokenService.createRefreshToken(testUser, testTenant);

        assertThat(rawToken).isNotBlank();

        byte[] rawBytes = Base64.getUrlDecoder().decode(rawToken);
        String hash = sha256Hex(rawBytes);

        RefreshToken found = refreshTokenRepository.findByTokenHash(hash).orElseThrow();
        assertThat(found.getUser().getId()).isEqualTo(testUser.getId());
        assertThat(found.getTenant().getId()).isEqualTo(testTenant.getId());
        assertThat(found.getRevokedAt()).isNull();
    }

    @Test
    void rotateCreatesNewAndRevokesOld() {
        String oldRaw = refreshTokenService.createRefreshToken(testUser, testTenant);
        RefreshTokenService.RotationResult result = refreshTokenService.rotateRefreshToken(oldRaw);
        String newRaw = result.newRawToken();

        assertThat(newRaw).isNotEqualTo(oldRaw);

        byte[] oldBytes = Base64.getUrlDecoder().decode(oldRaw);
        String oldHash = sha256Hex(oldBytes);
        RefreshToken oldToken = refreshTokenRepository.findByTokenHash(oldHash).orElseThrow();
        assertThat(oldToken.getRevokedAt()).isNotNull();

        byte[] newBytes = Base64.getUrlDecoder().decode(newRaw);
        String newHash = sha256Hex(newBytes);
        RefreshToken newToken = refreshTokenRepository.findByTokenHash(newHash).orElseThrow();
        assertThat(newToken.getRevokedAt()).isNull();
        assertThat(newToken.getRotatedFrom().getId()).isEqualTo(oldToken.getId());
    }

    @Test
    void reuseDetectionRevokesFamily() {
        String tokenA = refreshTokenService.createRefreshToken(testUser, testTenant);
        refreshTokenService.rotateRefreshToken(tokenA);

        assertThatThrownBy(() -> refreshTokenService.rotateRefreshToken(tokenA))
                .isInstanceOf(RefreshTokenReusedException.class);

        List<RefreshToken> allTokens = refreshTokenRepository
                .findAllByUser_IdAndTenant_Id(testUser.getId(), testTenant.getId());
        assertThat(allTokens).isNotEmpty();
        assertThat(allTokens).allMatch(t -> t.getRevokedAt() != null);
    }

    private static String sha256Hex(byte[] bytes) {
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
}
