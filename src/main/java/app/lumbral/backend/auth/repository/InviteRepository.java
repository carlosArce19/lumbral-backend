package app.lumbral.backend.auth.repository;

import app.lumbral.backend.auth.model.Invite;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface InviteRepository extends JpaRepository<Invite, UUID> {

    Optional<Invite> findByTokenHash(String tokenHash);

    @Query("SELECT i FROM Invite i JOIN FETCH i.tenant WHERE i.tokenHash = :tokenHash")
    Optional<Invite> findWithTenantByTokenHash(@Param("tokenHash") String tokenHash);

    List<Invite> findAllByTenant_Id(UUID tenantId);
}
