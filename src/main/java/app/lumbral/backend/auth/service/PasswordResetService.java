package app.lumbral.backend.auth.service;

import app.lumbral.backend.auth.model.PasswordReset;
import app.lumbral.backend.auth.model.User;
import app.lumbral.backend.auth.model.UserStatus;
import app.lumbral.backend.auth.repository.PasswordResetRepository;
import app.lumbral.backend.auth.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

@Service
public class PasswordResetService {

    private static final Duration RESET_TOKEN_TTL = Duration.ofHours(1);

    private final PasswordResetRepository passwordResetRepository;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final PasswordEncoder passwordEncoder;
    private final SecureRandom secureRandom = new SecureRandom();

    public PasswordResetService(PasswordResetRepository passwordResetRepository,
                                UserRepository userRepository,
                                RefreshTokenService refreshTokenService,
                                PasswordEncoder passwordEncoder) {
        this.passwordResetRepository = passwordResetRepository;
        this.userRepository = userRepository;
        this.refreshTokenService = refreshTokenService;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public void requestReset(String email) {
        String normalized = email.trim().toLowerCase();

        byte[] rawBytes = new byte[32];
        secureRandom.nextBytes(rawBytes);
        String tokenHash = sha256Hex(rawBytes);

        Optional<User> maybeUser = userRepository.findByEmail(normalized);
        if (maybeUser.isEmpty()) {
            return;
        }

        User user = maybeUser.get();
        if (user.getStatus() != UserStatus.ACTIVE) {
            return;
        }

        Instant now = Instant.now();
        passwordResetRepository.expireAllUnusedByUserId(user.getId(), now);

        PasswordReset resetRecord = new PasswordReset();
        resetRecord.setUser(user);
        resetRecord.setTokenHash(tokenHash);
        resetRecord.setExpiresAt(now.plus(RESET_TOKEN_TTL));
        passwordResetRepository.save(resetRecord);
    }

    @Transactional
    public void resetPassword(String rawToken, String newPassword) {
        byte[] rawBytes;
        try {
            rawBytes = Base64.getUrlDecoder().decode(rawToken);
        } catch (IllegalArgumentException e) {
            throw new InvalidTokenException("Invalid reset token.");
        }

        String tokenHash = sha256Hex(rawBytes);

        PasswordReset resetRecord = passwordResetRepository.findWithUserByTokenHash(tokenHash)
                .orElseThrow(() -> new InvalidTokenException("Invalid reset token."));

        if (resetRecord.getUsedAt() != null) {
            throw new InvalidTokenException("Invalid reset token.");
        }

        if (!resetRecord.getExpiresAt().isAfter(Instant.now())) {
            throw new InvalidTokenException("Reset token has expired.");
        }

        User user = resetRecord.getUser();
        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new InvalidTokenException("Invalid reset token.");
        }

        int updated = passwordResetRepository.markUsed(resetRecord.getId(), Instant.now());
        if (updated == 0) {
            throw new InvalidTokenException("Invalid reset token.");
        }

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        refreshTokenService.revokeAllForUser(user.getId());
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
