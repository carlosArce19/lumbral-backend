package app.lumbral.backend.auth.repository;

import app.lumbral.backend.auth.model.Invite;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface InviteRepository extends JpaRepository<Invite, UUID> {

    Optional<Invite> findByTokenHash(String tokenHash);

    List<Invite> findAllByTenant_Id(UUID tenantId);
}
