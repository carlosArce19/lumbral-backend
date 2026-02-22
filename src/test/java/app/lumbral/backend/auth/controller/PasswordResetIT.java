package app.lumbral.backend.auth.controller;

import app.lumbral.backend.auth.model.PasswordReset;
import app.lumbral.backend.auth.model.RefreshToken;
import app.lumbral.backend.auth.model.User;
import app.lumbral.backend.auth.model.UserStatus;
import app.lumbral.backend.auth.repository.PasswordResetRepository;
import app.lumbral.backend.auth.repository.RefreshTokenRepository;
import app.lumbral.backend.auth.repository.UserRepository;
import app.lumbral.backend.tenancy.model.Tenant;
import app.lumbral.backend.tenancy.model.TenantPlan;
import app.lumbral.backend.tenancy.repository.TenantRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.context.ImportTestcontainers;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ImportTestcontainers
class PasswordResetIT {

    @ServiceConnection
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private PasswordResetRepository passwordResetRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private static final String FORGOT_PATH = "/api/v1/auth/password/forgot";
    private static final String RESET_PATH = "/api/v1/auth/password/reset";

    // --- 1) Forgot: existing active user -> 200, token created ---

    @Test
    void forgotPassword_existingActiveUser_returns200() throws Exception {
        String email = uniqueEmail("forgot-active");
        User user = createUser(email, "old-password-123", UserStatus.ACTIVE);

        mockMvc.perform(post(FORGOT_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(forgotJson(email)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ok").value(true));

        List<PasswordReset> resets = passwordResetRepository.findAll().stream()
                .filter(r -> r.getUser().getId().equals(user.getId()))
                .toList();
        assertThat(resets).hasSize(1);
        assertThat(resets.getFirst().getUsedAt()).isNull();
        assertThat(resets.getFirst().getExpiresAt()).isAfter(Instant.now());
    }

    // --- 2) Forgot: non-existent email -> 200, no token created ---

    @Test
    void forgotPassword_nonExistentEmail_returns200() throws Exception {
        String email = uniqueEmail("nonexistent");

        long countBefore = passwordResetRepository.count();

        mockMvc.perform(post(FORGOT_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(forgotJson(email)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ok").value(true));

        assertThat(passwordResetRepository.count()).isEqualTo(countBefore);
    }

    // --- 3) Forgot: disabled user -> 200, no token created ---

    @Test
    void forgotPassword_disabledUser_returns200() throws Exception {
        String email = uniqueEmail("forgot-disabled");
        User user = createUser(email, "password-123", UserStatus.DISABLED);

        mockMvc.perform(post(FORGOT_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(forgotJson(email)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ok").value(true));

        List<PasswordReset> resets = passwordResetRepository.findAll().stream()
                .filter(r -> r.getUser().getId().equals(user.getId()))
                .toList();
        assertThat(resets).isEmpty();
    }

    // --- 4) Forgot: expires prior unused tokens ---

    @Test
    void forgotPassword_expiresPriorUnusedTokens() throws Exception {
        String email = uniqueEmail("forgot-expire");
        User user = createUser(email, "password-123", UserStatus.ACTIVE);

        String token1 = createResetToken(user, Instant.now().plusSeconds(86400), null);

        Instant beforeRequest = Instant.now();

        mockMvc.perform(post(FORGOT_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(forgotJson(email)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ok").value(true));

        List<PasswordReset> resets = passwordResetRepository.findAll().stream()
                .filter(r -> r.getUser().getId().equals(user.getId()))
                .toList();
        assertThat(resets).hasSize(2);

        String token1Hash = sha256Hex(Base64.getUrlDecoder().decode(token1));
        PasswordReset oldReset = passwordResetRepository.findByTokenHash(token1Hash).orElseThrow();
        assertThat(oldReset.getExpiresAt()).isBeforeOrEqualTo(Instant.now());
        assertThat(oldReset.getExpiresAt()).isAfterOrEqualTo(beforeRequest);
        assertThat(oldReset.getUsedAt()).isNull();
    }

    // --- 5) Reset: valid token -> 200, password changed, token marked used ---

    @Test
    void resetPassword_validToken_returns200() throws Exception {
        String email = uniqueEmail("reset-valid");
        User user = createUser(email, "old-password-123", UserStatus.ACTIVE);
        String rawToken = createResetToken(user, Instant.now().plusSeconds(86400), null);

        String newPassword = "new-secure-password-456";

        mockMvc.perform(post(RESET_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(resetJson(rawToken, newPassword)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ok").value(true));

        User updated = userRepository.findById(user.getId()).orElseThrow();
        assertThat(passwordEncoder.matches(newPassword, updated.getPasswordHash())).isTrue();

        String tokenHash = sha256Hex(Base64.getUrlDecoder().decode(rawToken));
        PasswordReset resetRecord = passwordResetRepository.findByTokenHash(tokenHash).orElseThrow();
        assertThat(resetRecord.getUsedAt()).isNotNull();
    }

    // --- 6) Reset: revokes refresh tokens across tenants ---

    @Test
    void resetPassword_revokesRefreshTokensAcrossTenants() throws Exception {
        String email = uniqueEmail("reset-revoke");
        User user = createUser(email, "old-password-123", UserStatus.ACTIVE);

        Tenant tenant1 = createTenant("rev-t1");
        Tenant tenant2 = createTenant("rev-t2");
        RefreshToken rt1 = createRefreshTokenRecord(user, tenant1);
        RefreshToken rt2 = createRefreshTokenRecord(user, tenant2);

        String rawToken = createResetToken(user, Instant.now().plusSeconds(86400), null);

        mockMvc.perform(post(RESET_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(resetJson(rawToken, "new-password-123")))
                .andExpect(status().isOk());

        RefreshToken reloaded1 = refreshTokenRepository.findById(rt1.getId()).orElseThrow();
        RefreshToken reloaded2 = refreshTokenRepository.findById(rt2.getId()).orElseThrow();
        assertThat(reloaded1.getRevokedAt()).isNotNull();
        assertThat(reloaded2.getRevokedAt()).isNotNull();
    }

    // --- 7) Reset: invalid token -> 401 ---

    @Test
    void resetPassword_invalidToken_returns401() throws Exception {
        byte[] randomBytes = new byte[32];
        new SecureRandom().nextBytes(randomBytes);
        String unknownToken = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        mockMvc.perform(post(RESET_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(resetJson(unknownToken, "new-password-123")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("invalid-token")))
                .andExpect(jsonPath("$.detail").value("Invalid reset token."));
    }

    // --- 8) Reset: expired token -> 401 ---

    @Test
    void resetPassword_expiredToken_returns401() throws Exception {
        String email = uniqueEmail("reset-expired");
        User user = createUser(email, "password-123", UserStatus.ACTIVE);
        String rawToken = createResetToken(user, Instant.now().minusSeconds(3600), null);

        mockMvc.perform(post(RESET_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(resetJson(rawToken, "new-password-123")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("invalid-token")))
                .andExpect(jsonPath("$.detail", containsString("expired")));
    }

    // --- 9) Reset: used token -> 401 ---

    @Test
    void resetPassword_usedToken_returns401() throws Exception {
        String email = uniqueEmail("reset-used");
        User user = createUser(email, "password-123", UserStatus.ACTIVE);
        String rawToken = createResetToken(user, Instant.now().plusSeconds(86400), Instant.now().minusSeconds(60));

        mockMvc.perform(post(RESET_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(resetJson(rawToken, "new-password-123")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("invalid-token")));
    }

    // --- 10) Reset: disabled user -> 401 ---

    @Test
    void resetPassword_disabledUser_returns401() throws Exception {
        String email = uniqueEmail("reset-disabled");
        User user = createUser(email, "password-123", UserStatus.ACTIVE);
        String rawToken = createResetToken(user, Instant.now().plusSeconds(86400), null);

        user.setStatus(UserStatus.DISABLED);
        userRepository.saveAndFlush(user);

        mockMvc.perform(post(RESET_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(resetJson(rawToken, "new-password-123")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("invalid-token")));
    }

    // --- 11) Reset: malformed token -> 401 ---

    @Test
    void resetPassword_malformedToken_returns401() throws Exception {
        mockMvc.perform(post(RESET_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(resetJson("!!!not-base64!!!", "new-password-123")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("invalid-token")));
    }

    // --- 12) Forgot: blank email -> 400 ---

    @Test
    void forgotPassword_blankEmail_returns400() throws Exception {
        mockMvc.perform(post(FORGOT_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(forgotJson("")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type", containsString("validation-error")));
    }

    // --- 13) Reset: concurrent use -> exactly one succeeds ---

    @Test
    void resetPassword_concurrentUse_exactlyOneSucceeds() throws Exception {
        String email = uniqueEmail("reset-concurrent");
        User user = createUser(email, "password-123", UserStatus.ACTIVE);
        String rawToken = createResetToken(user, Instant.now().plusSeconds(86400), null);

        CountDownLatch startGate = new CountDownLatch(1);
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger failureCount = new AtomicInteger(0);

        Runnable resetTask = () -> {
            try {
                startGate.await();
                int status = mockMvc.perform(post(RESET_PATH)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(resetJson(rawToken, "concurrent-pw-123")))
                        .andReturn()
                        .getResponse()
                        .getStatus();
                if (status == 200) {
                    successCount.incrementAndGet();
                } else if (status == 401) {
                    failureCount.incrementAndGet();
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };

        Thread t1 = new Thread(resetTask);
        Thread t2 = new Thread(resetTask);
        t1.start();
        t2.start();
        startGate.countDown();
        t1.join(5000);
        t2.join(5000);

        assertThat(successCount.get()).isEqualTo(1);
        assertThat(failureCount.get()).isEqualTo(1);

        String tokenHash = sha256Hex(Base64.getUrlDecoder().decode(rawToken));
        PasswordReset resetRecord = passwordResetRepository.findByTokenHash(tokenHash).orElseThrow();
        assertThat(resetRecord.getUsedAt()).isNotNull();
    }

    // --- HELPERS ---

    private static String uniqueEmail(String prefix) {
        return prefix + "-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
    }

    private User createUser(String email, String rawPassword, UserStatus status) {
        User user = new User();
        user.setEmail(email);
        user.setPasswordHash(passwordEncoder.encode(rawPassword));
        user.setStatus(status);
        return userRepository.saveAndFlush(user);
    }

    private Tenant createTenant(String codePrefix) {
        Tenant tenant = new Tenant();
        tenant.setName("Tenant " + codePrefix);
        tenant.setCode(codePrefix + "-" + UUID.randomUUID().toString().substring(0, 8));
        tenant.setPlan(TenantPlan.BASIC);
        return tenantRepository.saveAndFlush(tenant);
    }

    private String createResetToken(User user, Instant expiresAt, Instant usedAt) {
        byte[] rawBytes = new byte[32];
        new SecureRandom().nextBytes(rawBytes);

        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(rawBytes);
        String tokenHash = sha256Hex(rawBytes);

        PasswordReset reset = new PasswordReset();
        reset.setUser(user);
        reset.setTokenHash(tokenHash);
        reset.setExpiresAt(expiresAt);
        reset.setUsedAt(usedAt);
        passwordResetRepository.saveAndFlush(reset);

        return rawToken;
    }

    private RefreshToken createRefreshTokenRecord(User user, Tenant tenant) {
        byte[] rawBytes = new byte[32];
        new SecureRandom().nextBytes(rawBytes);

        RefreshToken rt = new RefreshToken();
        rt.setUser(user);
        rt.setTenant(tenant);
        rt.setTokenHash(sha256Hex(rawBytes));
        rt.setExpiresAt(Instant.now().plusSeconds(86400));
        return refreshTokenRepository.saveAndFlush(rt);
    }

    private static String forgotJson(String email) {
        return "{\"email\":\"" + email + "\"}";
    }

    private static String resetJson(String token, String newPassword) {
        return "{\"token\":\"" + token + "\",\"newPassword\":\"" + newPassword + "\"}";
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
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
