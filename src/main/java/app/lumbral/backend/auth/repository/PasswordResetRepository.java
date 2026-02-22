package app.lumbral.backend.auth.repository;

import app.lumbral.backend.auth.model.PasswordReset;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface PasswordResetRepository extends JpaRepository<PasswordReset, UUID> {

    Optional<PasswordReset> findByTokenHash(String tokenHash);

    @Query("SELECT p FROM PasswordReset p JOIN FETCH p.user WHERE p.tokenHash = :tokenHash")
    Optional<PasswordReset> findWithUserByTokenHash(@Param("tokenHash") String tokenHash);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("UPDATE PasswordReset p SET p.usedAt = :now WHERE p.id = :id AND p.usedAt IS NULL")
    int markUsed(@Param("id") UUID id, @Param("now") Instant now);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("UPDATE PasswordReset p SET p.expiresAt = :now " +
            "WHERE p.user.id = :userId AND p.usedAt IS NULL AND p.expiresAt > :now")
    int expireAllUnusedByUserId(@Param("userId") UUID userId, @Param("now") Instant now);
}
