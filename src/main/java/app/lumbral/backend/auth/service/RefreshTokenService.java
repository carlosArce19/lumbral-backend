package app.lumbral.backend.auth.service;

import app.lumbral.backend.auth.model.RefreshToken;
import app.lumbral.backend.auth.model.User;
import app.lumbral.backend.auth.repository.RefreshTokenRepository;
import app.lumbral.backend.tenancy.model.Tenant;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

@Service
public class RefreshTokenService {

    public record RotationResult(String newRawToken, UUID userId, UUID tenantId) {
    }

    public record TokenOwner(UUID userId, UUID tenantId) {
    }

    private final RefreshTokenRepository repository;
    private final Duration refreshTokenTtl;
    private final SecureRandom secureRandom = new SecureRandom();

    public RefreshTokenService(RefreshTokenRepository repository,
                                @Value("${app.jwt.refresh-token-ttl}") Duration refreshTokenTtl) {
        this.repository = repository;
        this.refreshTokenTtl = refreshTokenTtl;
    }

    @Transactional
    public String createRefreshToken(User user, Tenant tenant) {
        byte[] rawBytes = new byte[32];
        secureRandom.nextBytes(rawBytes);

        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(rawBytes);
        String tokenHash = sha256Hex(rawBytes);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setTenant(tenant);
        refreshToken.setTokenHash(tokenHash);
        refreshToken.setExpiresAt(Instant.now().plus(refreshTokenTtl));

        repository.save(refreshToken);

        return rawToken;
    }

    @Transactional(noRollbackFor = RefreshTokenReusedException.class)
    public RotationResult rotateRefreshToken(String rawToken) {
        RefreshToken oldToken = resolveToken(rawToken);

        if (oldToken.getRevokedAt() != null) {
            UUID userId = oldToken.getUser().getId();
            UUID tenantId = oldToken.getTenant().getId();
            revokeAllForUserAndTenant(userId, tenantId);
            throw new RefreshTokenReusedException(userId, tenantId);
        }

        if (oldToken.getExpiresAt().isBefore(Instant.now())) {
            throw new InvalidTokenException("Refresh token expired");
        }

        Instant now = Instant.now();
        oldToken.setRevokedAt(now);
        repository.save(oldToken);

        byte[] newRawBytes = new byte[32];
        secureRandom.nextBytes(newRawBytes);
        String newRawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(newRawBytes);
        String newTokenHash = sha256Hex(newRawBytes);

        RefreshToken newToken = new RefreshToken();
        newToken.setUser(oldToken.getUser());
        newToken.setTenant(oldToken.getTenant());
        newToken.setTokenHash(newTokenHash);
        newToken.setExpiresAt(now.plus(refreshTokenTtl));
        newToken.setRotatedFrom(oldToken);

        repository.save(newToken);

        return new RotationResult(newRawToken,
                oldToken.getUser().getId(),
                oldToken.getTenant().getId());
    }

    @Transactional(readOnly = true)
    public TokenOwner findTokenOwner(String rawToken) {
        RefreshToken token = resolveToken(rawToken);
        return new TokenOwner(token.getUser().getId(), token.getTenant().getId());
    }

    @Transactional
    public void revokeAllForUserAndTenant(UUID userId, UUID tenantId) {
        repository.revokeAllByUserIdAndTenantId(userId, tenantId, Instant.now());
    }

    @Transactional
    public void revokeAllForUser(UUID userId) {
        repository.revokeAllByUserId(userId, Instant.now());
    }

    private RefreshToken resolveToken(String rawToken) {
        byte[] rawBytes;
        try {
            rawBytes = Base64.getUrlDecoder().decode(rawToken);
        } catch (IllegalArgumentException e) {
            throw new InvalidTokenException("Invalid refresh token format");
        }

        String tokenHash = sha256Hex(rawBytes);
        return repository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new InvalidTokenException("Refresh token not found"));
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
