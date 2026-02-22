package app.lumbral.backend.policy;

import app.lumbral.backend.tenancy.model.TenantPlan;

import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public final class CapabilityResolver {

    private static final Map<TenantPlan, Set<Capability>> PLAN_CAPABILITIES;
    private static final Map<Action, Capability> ACTION_CAPABILITY;

    static {
        EnumMap<TenantPlan, Set<Capability>> plans = new EnumMap<>(TenantPlan.class);
        plans.put(TenantPlan.BASIC, Collections.unmodifiableSet(EnumSet.of(
                Capability.CAP_SITE
        )));
        plans.put(TenantPlan.MID, Collections.unmodifiableSet(EnumSet.of(
                Capability.CAP_SITE,
                Capability.CAP_STORE
        )));
        plans.put(TenantPlan.PRO, Collections.unmodifiableSet(EnumSet.of(
                Capability.CAP_SITE,
                Capability.CAP_STORE,
                Capability.CAP_SCHEDULING
        )));
        PLAN_CAPABILITIES = Collections.unmodifiableMap(plans);

        EnumMap<Action, Capability> actions = new EnumMap<>(Action.class);
        actions.put(Action.SITE_EDIT, Capability.CAP_SITE);
        actions.put(Action.SITE_PUBLISH, Capability.CAP_SITE);
        actions.put(Action.PRODUCT_MANAGE, Capability.CAP_STORE);
        actions.put(Action.CATEGORY_MANAGE, Capability.CAP_STORE);
        actions.put(Action.PRICING_MANAGE, Capability.CAP_STORE);
        actions.put(Action.PRODUCT_MEDIA_MANAGE, Capability.CAP_STORE);
        actions.put(Action.ORDER_VIEW, Capability.CAP_STORE);
        actions.put(Action.ORDER_MANAGE, Capability.CAP_STORE);
        actions.put(Action.REFUND_MANAGE, Capability.CAP_STORE);
        actions.put(Action.SALE_CREATE, Capability.CAP_STORE);
        actions.put(Action.SERVICE_MANAGE, Capability.CAP_SCHEDULING);
        actions.put(Action.BOOKING_MANAGE, Capability.CAP_SCHEDULING);
        // PAYMENT_SETTINGS_MANAGE, DOMAIN_MANAGE, STAFF_MANAGE, TENANT_SETTINGS_MANAGE
        // have no capability requirement — role gating is sufficient
        ACTION_CAPABILITY = Collections.unmodifiableMap(actions);
    }

    private CapabilityResolver() {
    }

    public static Set<Capability> forPlan(TenantPlan plan) {
        return PLAN_CAPABILITIES.getOrDefault(plan, Collections.emptySet());
    }

    public static Optional<Capability> requiredFor(Action action) {
        return Optional.ofNullable(ACTION_CAPABILITY.get(action));
    }
}
