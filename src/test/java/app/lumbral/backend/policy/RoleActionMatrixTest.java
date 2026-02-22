package app.lumbral.backend.policy;

import app.lumbral.backend.auth.model.MembershipRole;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class RoleActionMatrixTest {

    private static final Set<Action> STAFF_ALLOWED = EnumSet.of(
            Action.PRODUCT_MANAGE,
            Action.CATEGORY_MANAGE,
            Action.PRICING_MANAGE,
            Action.PRODUCT_MEDIA_MANAGE,
            Action.ORDER_VIEW,
            Action.ORDER_MANAGE,
            Action.REFUND_MANAGE,
            Action.SALE_CREATE,
            Action.SERVICE_MANAGE,
            Action.BOOKING_MANAGE
    );

    private static final Set<Action> STAFF_DENIED = EnumSet.of(
            Action.SITE_EDIT,
            Action.SITE_PUBLISH,
            Action.PAYMENT_SETTINGS_MANAGE,
            Action.DOMAIN_MANAGE,
            Action.STAFF_MANAGE,
            Action.TENANT_SETTINGS_MANAGE
    );

    @Test
    void adminAllowsAllActions() {
        for (Action action : Action.values()) {
            assertThat(RoleActionMatrix.isAllowed(MembershipRole.ADMIN, action))
                    .as("ADMIN should be allowed %s", action)
                    .isTrue();
        }
    }

    @Test
    void staffAllowedActions() {
        for (Action action : STAFF_ALLOWED) {
            assertThat(RoleActionMatrix.isAllowed(MembershipRole.STAFF, action))
                    .as("STAFF should be allowed %s", action)
                    .isTrue();
        }
    }

    @Test
    void staffDeniedActions() {
        for (Action action : STAFF_DENIED) {
            assertThat(RoleActionMatrix.isAllowed(MembershipRole.STAFF, action))
                    .as("STAFF should be denied %s", action)
                    .isFalse();
        }
    }

    @Test
    void editorAllowedActions() {
        assertThat(RoleActionMatrix.isAllowed(MembershipRole.EDITOR, Action.SITE_EDIT))
                .isTrue();
    }

    @Test
    void editorDeniedActions() {
        for (Action action : Action.values()) {
            if (action == Action.SITE_EDIT) continue;
            assertThat(RoleActionMatrix.isAllowed(MembershipRole.EDITOR, action))
                    .as("EDITOR should be denied %s", action)
                    .isFalse();
        }
    }
}
