package app.lumbral.backend.policy;

import app.lumbral.backend.tenancy.model.TenantPlan;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class CapabilityResolverTest {

    @Test
    void basicPlanHasOnlySite() {
        Set<Capability> caps = CapabilityResolver.forPlan(TenantPlan.BASIC);
        assertThat(caps).containsExactlyInAnyOrder(Capability.CAP_SITE);
    }

    @Test
    void midPlanHasSiteAndStore() {
        Set<Capability> caps = CapabilityResolver.forPlan(TenantPlan.MID);
        assertThat(caps).containsExactlyInAnyOrder(Capability.CAP_SITE, Capability.CAP_STORE);
    }

    @Test
    void proPlanHasAll() {
        Set<Capability> caps = CapabilityResolver.forPlan(TenantPlan.PRO);
        assertThat(caps).containsExactlyInAnyOrder(
                Capability.CAP_SITE, Capability.CAP_STORE, Capability.CAP_SCHEDULING);
    }

    @Test
    void siteActionsRequireCapSite() {
        assertThat(CapabilityResolver.requiredFor(Action.SITE_EDIT))
                .isEqualTo(Optional.of(Capability.CAP_SITE));
        assertThat(CapabilityResolver.requiredFor(Action.SITE_PUBLISH))
                .isEqualTo(Optional.of(Capability.CAP_SITE));
    }

    @Test
    void storeActionsRequireCapStore() {
        assertThat(CapabilityResolver.requiredFor(Action.PRODUCT_MANAGE))
                .isEqualTo(Optional.of(Capability.CAP_STORE));
        assertThat(CapabilityResolver.requiredFor(Action.ORDER_VIEW))
                .isEqualTo(Optional.of(Capability.CAP_STORE));
    }

    @Test
    void schedulingActionsRequireCapScheduling() {
        assertThat(CapabilityResolver.requiredFor(Action.SERVICE_MANAGE))
                .isEqualTo(Optional.of(Capability.CAP_SCHEDULING));
        assertThat(CapabilityResolver.requiredFor(Action.BOOKING_MANAGE))
                .isEqualTo(Optional.of(Capability.CAP_SCHEDULING));
    }

    @Test
    void adminSettingsRequireNoCap() {
        assertThat(CapabilityResolver.requiredFor(Action.STAFF_MANAGE)).isEmpty();
        assertThat(CapabilityResolver.requiredFor(Action.DOMAIN_MANAGE)).isEmpty();
        assertThat(CapabilityResolver.requiredFor(Action.PAYMENT_SETTINGS_MANAGE)).isEmpty();
        assertThat(CapabilityResolver.requiredFor(Action.TENANT_SETTINGS_MANAGE)).isEmpty();
    }
}
