package app.lumbral.backend.auth.repository;

import app.lumbral.backend.auth.model.MembershipStatus;
import app.lumbral.backend.auth.model.TenantMembership;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface TenantMembershipRepository extends JpaRepository<TenantMembership, UUID> {

    Optional<TenantMembership> findByUser_IdAndTenant_Id(UUID userId, UUID tenantId);

    List<TenantMembership> findAllByUser_IdAndStatus(UUID userId, MembershipStatus status);

    List<TenantMembership> findAllByTenant_Id(UUID tenantId);
}
