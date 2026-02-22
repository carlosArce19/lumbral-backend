package app.lumbral.backend.policy;

import app.lumbral.backend.auth.model.MembershipRole;

import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

public final class RoleActionMatrix {

    private static final Map<MembershipRole, Set<Action>> MATRIX;

    static {
        EnumMap<MembershipRole, Set<Action>> map = new EnumMap<>(MembershipRole.class);

        map.put(MembershipRole.STAFF, Collections.unmodifiableSet(EnumSet.of(
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
        )));

        map.put(MembershipRole.EDITOR, Collections.unmodifiableSet(EnumSet.of(
                Action.SITE_EDIT
        )));

        MATRIX = Collections.unmodifiableMap(map);
    }

    private RoleActionMatrix() {
    }

    public static boolean isAllowed(MembershipRole role, Action action) {
        if (role == MembershipRole.ADMIN) {
            return true;
        }
        Set<Action> allowed = MATRIX.get(role);
        return allowed != null && allowed.contains(action);
    }
}
