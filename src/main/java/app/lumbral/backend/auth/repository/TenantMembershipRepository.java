package app.lumbral.backend.auth.repository;

import app.lumbral.backend.auth.model.MembershipStatus;
import app.lumbral.backend.auth.model.TenantMembership;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface TenantMembershipRepository extends JpaRepository<TenantMembership, UUID> {

    Optional<TenantMembership> findByUser_IdAndTenant_Id(UUID userId, UUID tenantId);

    @Query("SELECT m FROM TenantMembership m JOIN FETCH m.tenant WHERE m.user.id = :userId AND m.tenant.id = :tenantId")
    Optional<TenantMembership> findWithTenantByUserIdAndTenantId(@Param("userId") UUID userId, @Param("tenantId") UUID tenantId);

    List<TenantMembership> findAllByUser_IdAndStatus(UUID userId, MembershipStatus status);

    List<TenantMembership> findAllByTenant_Id(UUID tenantId);
}
