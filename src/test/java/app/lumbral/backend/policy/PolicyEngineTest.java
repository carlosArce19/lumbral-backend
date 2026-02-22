package app.lumbral.backend.policy;

import app.lumbral.backend.auth.model.MembershipRole;
import app.lumbral.backend.auth.model.MembershipStatus;
import app.lumbral.backend.tenancy.model.TenantPlan;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PolicyEngineTest {

    private TenantContext ctx(MembershipRole role, MembershipStatus status, TenantPlan plan) {
        return new TenantContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                role,
                UUID.randomUUID(),
                status,
                plan
        );
    }

    @Test
    void activeMembershipWithPermittedActionPasses() {
        TenantContext admin = ctx(MembershipRole.ADMIN, MembershipStatus.ACTIVE, TenantPlan.PRO);
        for (Action action : Action.values()) {
            assertThatCode(() -> PolicyEngine.require(admin, action))
                    .as("ADMIN+ACTIVE+PRO should pass %s", action)
                    .doesNotThrowAnyException();
        }
    }

    @Test
    void disabledMembershipDeniesEverything() {
        TenantContext disabled = ctx(MembershipRole.ADMIN, MembershipStatus.DISABLED, TenantPlan.PRO);
        assertThatThrownBy(() -> PolicyEngine.require(disabled, Action.SITE_EDIT))
                .isInstanceOf(AccessDeniedException.class)
                .extracting(e -> ((AccessDeniedException) e).getReason())
                .isEqualTo(AccessDeniedException.Reason.MEMBERSHIP_NOT_ACTIVE);
    }

    @Test
    void invitedMembershipDeniesEverything() {
        TenantContext invited = ctx(MembershipRole.STAFF, MembershipStatus.INVITED, TenantPlan.PRO);
        assertThatThrownBy(() -> PolicyEngine.require(invited, Action.PRODUCT_MANAGE))
                .isInstanceOf(AccessDeniedException.class)
                .extracting(e -> ((AccessDeniedException) e).getReason())
                .isEqualTo(AccessDeniedException.Reason.MEMBERSHIP_NOT_ACTIVE);
    }

    @Test
    void staffDeniedSitePublish() {
        TenantContext staff = ctx(MembershipRole.STAFF, MembershipStatus.ACTIVE, TenantPlan.PRO);
        assertThatThrownBy(() -> PolicyEngine.require(staff, Action.SITE_PUBLISH))
                .isInstanceOf(AccessDeniedException.class)
                .extracting(e -> ((AccessDeniedException) e).getReason())
                .isEqualTo(AccessDeniedException.Reason.ACTION_NOT_PERMITTED);
    }

    @Test
    void editorDeniedProductManage() {
        TenantContext editor = ctx(MembershipRole.EDITOR, MembershipStatus.ACTIVE, TenantPlan.PRO);
        assertThatThrownBy(() -> PolicyEngine.require(editor, Action.PRODUCT_MANAGE))
                .isInstanceOf(AccessDeniedException.class)
                .extracting(e -> ((AccessDeniedException) e).getReason())
                .isEqualTo(AccessDeniedException.Reason.ACTION_NOT_PERMITTED);
    }

    @Test
    void basicPlanDeniesStoreActions() {
        TenantContext admin = ctx(MembershipRole.ADMIN, MembershipStatus.ACTIVE, TenantPlan.BASIC);
        assertThatThrownBy(() -> PolicyEngine.require(admin, Action.PRODUCT_MANAGE))
                .isInstanceOf(AccessDeniedException.class)
                .extracting(e -> ((AccessDeniedException) e).getReason())
                .isEqualTo(AccessDeniedException.Reason.CAPABILITY_MISSING);
    }

    @Test
    void midPlanDeniesScheduling() {
        TenantContext staff = ctx(MembershipRole.STAFF, MembershipStatus.ACTIVE, TenantPlan.MID);
        assertThatThrownBy(() -> PolicyEngine.require(staff, Action.SERVICE_MANAGE))
                .isInstanceOf(AccessDeniedException.class)
                .extracting(e -> ((AccessDeniedException) e).getReason())
                .isEqualTo(AccessDeniedException.Reason.CAPABILITY_MISSING);
    }

    @Test
    void midPlanAllowsStoreActions() {
        TenantContext staff = ctx(MembershipRole.STAFF, MembershipStatus.ACTIVE, TenantPlan.MID);
        assertThatCode(() -> PolicyEngine.require(staff, Action.PRODUCT_MANAGE))
                .doesNotThrowAnyException();
    }
}
