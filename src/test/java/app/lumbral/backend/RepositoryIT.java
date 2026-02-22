package app.lumbral.backend;

import app.lumbral.backend.auth.model.*;
import app.lumbral.backend.auth.repository.*;
import app.lumbral.backend.events.consumption.EventConsumption;
import app.lumbral.backend.events.consumption.EventConsumptionRepository;
import app.lumbral.backend.tenancy.model.Tenant;
import app.lumbral.backend.tenancy.model.TenantPlan;
import app.lumbral.backend.tenancy.repository.TenantRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.boot.testcontainers.context.ImportTestcontainers;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.PostgreSQLContainer;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DataJpaTest
@ImportTestcontainers
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class RepositoryIT {

    @ServiceConnection
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private TestEntityManager em;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private TenantMembershipRepository membershipRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private EventConsumptionRepository eventConsumptionRepository;

    // ---- helpers ----

    private User createUser(String email) {
        User u = new User();
        u.setEmail(email);
        u.setPasswordHash("hash");
        u.setStatus(UserStatus.ACTIVE);
        return u;
    }

    private Tenant createTenant(String code) {
        Tenant t = new Tenant();
        t.setName("Tenant " + code);
        t.setCode(code);
        t.setPlan(TenantPlan.BASIC);
        return t;
    }

    // ---- tests ----

    @Test
    void saveAndFindUser() {
        User saved = userRepository.saveAndFlush(createUser("alice@example.com"));

        assertThat(saved.getId()).isNotNull();
        assertThat(saved.getCreatedAt()).isNotNull();
        assertThat(saved.getUpdatedAt()).isNotNull();

        Optional<User> found = userRepository.findByEmail("alice@example.com");
        assertThat(found).isPresent();
        assertThat(found.get().getId()).isEqualTo(saved.getId());
    }

    @Test
    void userEmailUniqueness() {
        userRepository.saveAndFlush(createUser("dup@example.com"));

        assertThatThrownBy(() -> userRepository.saveAndFlush(createUser("dup@example.com")))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
    }

    @Test
    void saveAndFindTenant() {
        Tenant saved = tenantRepository.saveAndFlush(createTenant("acme"));

        assertThat(saved.getId()).isNotNull();
        assertThat(saved.getCreatedAt()).isNotNull();

        Optional<Tenant> found = tenantRepository.findByCode("acme");
        assertThat(found).isPresent();
        assertThat(found.get().getId()).isEqualTo(saved.getId());
    }

    @Test
    void saveMembershipWithFkConstraint() {
        User user = userRepository.saveAndFlush(createUser("member@example.com"));
        Tenant tenant = tenantRepository.saveAndFlush(createTenant("org1"));

        TenantMembership m = new TenantMembership();
        m.setUser(user);
        m.setTenant(tenant);
        m.setRole(MembershipRole.ADMIN);
        m.setStatus(MembershipStatus.ACTIVE);

        TenantMembership saved = membershipRepository.saveAndFlush(m);

        assertThat(saved.getId()).isNotNull();

        Optional<TenantMembership> found =
                membershipRepository.findByUser_IdAndTenant_Id(user.getId(), tenant.getId());
        assertThat(found).isPresent();
        assertThat(found.get().getRole()).isEqualTo(MembershipRole.ADMIN);
    }

    @Test
    void membershipUniqueness() {
        User user = userRepository.saveAndFlush(createUser("unique@example.com"));
        Tenant tenant = tenantRepository.saveAndFlush(createTenant("org2"));

        TenantMembership m1 = new TenantMembership();
        m1.setUser(user);
        m1.setTenant(tenant);
        m1.setRole(MembershipRole.STAFF);
        m1.setStatus(MembershipStatus.ACTIVE);
        membershipRepository.saveAndFlush(m1);

        TenantMembership m2 = new TenantMembership();
        m2.setUser(user);
        m2.setTenant(tenant);
        m2.setRole(MembershipRole.EDITOR);
        m2.setStatus(MembershipStatus.INVITED);

        assertThatThrownBy(() -> membershipRepository.saveAndFlush(m2))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
    }

    @Test
    void refreshTokenHashUniqueness() {
        User user = userRepository.saveAndFlush(createUser("token@example.com"));
        Tenant tenant = tenantRepository.saveAndFlush(createTenant("org3"));

        RefreshToken rt1 = new RefreshToken();
        rt1.setUser(user);
        rt1.setTenant(tenant);
        rt1.setTokenHash("same-hash");
        rt1.setExpiresAt(Instant.now().plus(1, ChronoUnit.HOURS));
        refreshTokenRepository.saveAndFlush(rt1);

        RefreshToken rt2 = new RefreshToken();
        rt2.setUser(user);
        rt2.setTenant(tenant);
        rt2.setTokenHash("same-hash");
        rt2.setExpiresAt(Instant.now().plus(2, ChronoUnit.HOURS));

        assertThatThrownBy(() -> refreshTokenRepository.saveAndFlush(rt2))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
    }

    @Test
    void eventConsumptionDedup() {
        UUID eventId = UUID.randomUUID();

        EventConsumption ec1 = new EventConsumption();
        ec1.setConsumerName("mailer");
        ec1.setEventId(eventId);
        eventConsumptionRepository.saveAndFlush(ec1);

        assertThat(eventConsumptionRepository.existsByConsumerNameAndEventId("mailer", eventId))
                .isTrue();

        EventConsumption ec2 = new EventConsumption();
        ec2.setConsumerName("mailer");
        ec2.setEventId(eventId);

        assertThatThrownBy(() -> eventConsumptionRepository.saveAndFlush(ec2))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
    }
}
