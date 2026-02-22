package app.lumbral.backend.auth.repository;

import app.lumbral.backend.auth.model.PasswordReset;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface PasswordResetRepository extends JpaRepository<PasswordReset, UUID> {

    Optional<PasswordReset> findByTokenHash(String tokenHash);
}
