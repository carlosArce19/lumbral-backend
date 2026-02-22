package app.lumbral.backend.policy;

import app.lumbral.backend.auth.model.MembershipRole;
import app.lumbral.backend.auth.model.MembershipStatus;
import app.lumbral.backend.tenancy.model.TenantPlan;

import java.util.UUID;

public record TenantContext(
        UUID tenantId,
        UUID userId,
        MembershipRole role,
        UUID membershipId,
        MembershipStatus membershipStatus,
        TenantPlan tenantPlan
) {
}
