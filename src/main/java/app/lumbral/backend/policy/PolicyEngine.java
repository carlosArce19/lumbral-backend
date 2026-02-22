package app.lumbral.backend.policy;

import app.lumbral.backend.auth.model.MembershipStatus;

import java.util.Objects;

public final class PolicyEngine {

    private PolicyEngine() {
    }

    public static void require(TenantContext ctx, Action action) {
        Objects.requireNonNull(ctx, "TenantContext must not be null");
        Objects.requireNonNull(ctx.membershipStatus(), "membershipStatus must not be null");
        Objects.requireNonNull(ctx.role(), "role must not be null");
        Objects.requireNonNull(ctx.tenantPlan(), "tenantPlan must not be null");
        Objects.requireNonNull(action, "action must not be null");

        if (ctx.membershipStatus() != MembershipStatus.ACTIVE) {
            throw new AccessDeniedException(
                    AccessDeniedException.Reason.MEMBERSHIP_NOT_ACTIVE, action);
        }

        if (!RoleActionMatrix.isAllowed(ctx.role(), action)) {
            throw new AccessDeniedException(
                    AccessDeniedException.Reason.ACTION_NOT_PERMITTED, action);
        }

        CapabilityResolver.requiredFor(action)
                .filter(required -> !CapabilityResolver.forPlan(ctx.tenantPlan()).contains(required))
                .ifPresent(required -> {
                    throw new AccessDeniedException(
                            AccessDeniedException.Reason.CAPABILITY_MISSING, action);
                });
    }
}
