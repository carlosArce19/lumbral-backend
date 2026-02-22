package app.lumbral.backend.auth.controller;

import app.lumbral.backend.auth.model.*;
import app.lumbral.backend.auth.repository.InviteRepository;
import app.lumbral.backend.auth.repository.TenantMembershipRepository;
import app.lumbral.backend.auth.repository.UserRepository;
import app.lumbral.backend.tenancy.model.Tenant;
import app.lumbral.backend.tenancy.model.TenantPlan;
import app.lumbral.backend.tenancy.repository.TenantRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.context.ImportTestcontainers;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ImportTestcontainers
class InviteAcceptIT {

    @ServiceConnection
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private InviteRepository inviteRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private TenantMembershipRepository membershipRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private static final String PASSWORD = "test-password-123";

    private Tenant tenant;

    @BeforeEach
    void setUp() {
        String unique = UUID.randomUUID().toString().substring(0, 8);

        tenant = new Tenant();
        tenant.setName("Invite Corp");
        tenant.setCode("inv-" + unique);
        tenant.setPlan(TenantPlan.BASIC);
        tenant = tenantRepository.saveAndFlush(tenant);
    }

    // --- 1) New user accepts invite -> 200 SIGNED_IN ---

    @Test
    void acceptNewUser_returns200() throws Exception {
        String unique = UUID.randomUUID().toString().substring(0, 8);
        String email = "newuser-" + unique + "@example.com";

        String rawToken = createInviteToken(tenant, email, MembershipRole.STAFF,
                Instant.now().plusSeconds(86400), null);

        MvcResult result = mockMvc.perform(post("/api/v1/auth/invites/accept")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(acceptJson(rawToken, PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mode").value("SIGNED_IN"))
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.accessTokenExpiresInSeconds").value(900))
                .andExpect(jsonPath("$.tenant.tenantId").value(tenant.getId().toString()))
                .andExpect(jsonPath("$.tenant.name").value("Invite Corp"))
                .andReturn();

        assertRefreshCookiePresent(result);

        Optional<User> createdUser = userRepository.findByEmail(email);
        assertThat(createdUser).isPresent();
        assertThat(createdUser.get().getStatus()).isEqualTo(UserStatus.ACTIVE);

        Optional<TenantMembership> membership = membershipRepository
                .findByUser_IdAndTenant_Id(createdUser.get().getId(), tenant.getId());
        assertThat(membership).isPresent();
        assertThat(membership.get().getStatus()).isEqualTo(MembershipStatus.ACTIVE);
        assertThat(membership.get().getRole()).isEqualTo(MembershipRole.STAFF);
    }

    // --- 2) Existing user accepts invite -> 200 ---

    @Test
    void acceptExistingUser_returns200() throws Exception {
        String unique = UUID.randomUUID().toString().substring(0, 8);
        String email = "existing-" + unique + "@example.com";

        User user = createUser(email, PASSWORD, UserStatus.ACTIVE);

        String rawToken = createInviteToken(tenant, email, MembershipRole.EDITOR,
                Instant.now().plusSeconds(86400), null);

        mockMvc.perform(post("/api/v1/auth/invites/accept")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(acceptJson(rawToken, PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mode").value("SIGNED_IN"))
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.tenant.tenantId").value(tenant.getId().toString()));

        Optional<TenantMembership> membership = membershipRepository
                .findByUser_IdAndTenant_Id(user.getId(), tenant.getId());
        assertThat(membership).isPresent();
        assertThat(membership.get().getStatus()).isEqualTo(MembershipStatus.ACTIVE);
        assertThat(membership.get().getRole()).isEqualTo(MembershipRole.EDITOR);
    }

    // --- 3) Existing user with INVITED membership -> activates ---

    @Test
    void acceptExistingUserWithInvitedMembership_activates() throws Exception {
        String unique = UUID.randomUUID().toString().substring(0, 8);
        String email = "invited-" + unique + "@example.com";

        User user = createUser(email, PASSWORD, UserStatus.ACTIVE);

        TenantMembership membership = new TenantMembership();
        membership.setUser(user);
        membership.setTenant(tenant);
        membership.setRole(MembershipRole.STAFF);
        membership.setStatus(MembershipStatus.INVITED);
        membership = membershipRepository.saveAndFlush(membership);

        String rawToken = createInviteToken(tenant, email, MembershipRole.STAFF,
                Instant.now().plusSeconds(86400), null);

        mockMvc.perform(post("/api/v1/auth/invites/accept")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(acceptJson(rawToken, PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mode").value("SIGNED_IN"));

        TenantMembership updated = membershipRepository.findById(membership.getId()).orElseThrow();
        assertThat(updated.getStatus()).isEqualTo(MembershipStatus.ACTIVE);
    }

    // --- 4) Invalid token -> 401 ---

    @Test
    void acceptInvalidToken_returns401() throws Exception {
        byte[] randomBytes = new byte[32];
        new SecureRandom().nextBytes(randomBytes);
        String unknownToken = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        mockMvc.perform(post("/api/v1/auth/invites/accept")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(acceptJson(unknownToken, PASSWORD)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("invalid-token")))
                .andExpect(jsonPath("$.detail", containsString("Invalid invite token")));
    }

    // --- 5) Expired token -> 401 ---

    @Test
    void acceptExpiredToken_returns401() throws Exception {
        String unique = UUID.randomUUID().toString().substring(0, 8);
        String email = "expired-" + unique + "@example.com";

        String rawToken = createInviteToken(tenant, email, MembershipRole.STAFF,
                Instant.now().minusSeconds(3600), null);

        mockMvc.perform(post("/api/v1/auth/invites/accept")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(acceptJson(rawToken, PASSWORD)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("invalid-token")))
                .andExpect(jsonPath("$.detail", containsString("expired")));
    }

    // --- 6) Already accepted -> 409 ---

    @Test
    void acceptAlreadyAccepted_returns409() throws Exception {
        String unique = UUID.randomUUID().toString().substring(0, 8);
        String email = "accepted-" + unique + "@example.com";

        String rawToken = createInviteToken(tenant, email, MembershipRole.STAFF,
                Instant.now().plusSeconds(86400), Instant.now().minusSeconds(60));

        mockMvc.perform(post("/api/v1/auth/invites/accept")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(acceptJson(rawToken, PASSWORD)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type", containsString("invite-already-accepted")));
    }

    // --- 7) Existing user wrong password -> 401 ---

    @Test
    void acceptExistingUserWrongPassword_returns401() throws Exception {
        String unique = UUID.randomUUID().toString().substring(0, 8);
        String email = "wrongpw-" + unique + "@example.com";

        createUser(email, PASSWORD, UserStatus.ACTIVE);

        String rawToken = createInviteToken(tenant, email, MembershipRole.STAFF,
                Instant.now().plusSeconds(86400), null);

        mockMvc.perform(post("/api/v1/auth/invites/accept")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(acceptJson(rawToken, "wrong-password")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("auth-failed")))
                .andExpect(jsonPath("$.detail").value("Invalid email or password."));
    }

    // --- 8) Existing user disabled -> 401 ---

    @Test
    void acceptExistingUserDisabled_returns401() throws Exception {
        String unique = UUID.randomUUID().toString().substring(0, 8);
        String email = "disabled-" + unique + "@example.com";

        createUser(email, PASSWORD, UserStatus.DISABLED);

        String rawToken = createInviteToken(tenant, email, MembershipRole.STAFF,
                Instant.now().plusSeconds(86400), null);

        mockMvc.perform(post("/api/v1/auth/invites/accept")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(acceptJson(rawToken, PASSWORD)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("auth-failed")));
    }

    // --- 9) Disabled membership -> 403 ---

    @Test
    void acceptDisabledMembership_returns403() throws Exception {
        String unique = UUID.randomUUID().toString().substring(0, 8);
        String email = "dismem-" + unique + "@example.com";

        User user = createUser(email, PASSWORD, UserStatus.ACTIVE);

        TenantMembership membership = new TenantMembership();
        membership.setUser(user);
        membership.setTenant(tenant);
        membership.setRole(MembershipRole.STAFF);
        membership.setStatus(MembershipStatus.DISABLED);
        membershipRepository.saveAndFlush(membership);

        String rawToken = createInviteToken(tenant, email, MembershipRole.STAFF,
                Instant.now().plusSeconds(86400), null);

        mockMvc.perform(post("/api/v1/auth/invites/accept")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(acceptJson(rawToken, PASSWORD)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.type", containsString("no-active-membership")));
    }

    // --- HELPERS ---

    private String createInviteToken(Tenant tenant, String email, MembershipRole role,
                                     Instant expiresAt, Instant acceptedAt) {
        byte[] rawBytes = new byte[32];
        new SecureRandom().nextBytes(rawBytes);

        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(rawBytes);
        String tokenHash = sha256Hex(rawBytes);

        Invite invite = new Invite();
        invite.setTenant(tenant);
        invite.setEmail(email);
        invite.setRole(role);
        invite.setTokenHash(tokenHash);
        invite.setExpiresAt(expiresAt);
        invite.setAcceptedAt(acceptedAt);
        inviteRepository.saveAndFlush(invite);

        return rawToken;
    }

    private User createUser(String email, String rawPassword, UserStatus status) {
        User user = new User();
        user.setEmail(email);
        user.setPasswordHash(passwordEncoder.encode(rawPassword));
        user.setStatus(status);
        return userRepository.saveAndFlush(user);
    }

    private static String acceptJson(String token, String password) {
        return "{\"token\":\"" + token + "\",\"password\":\"" + password + "\"}";
    }

    private static void assertRefreshCookiePresent(MvcResult result) {
        String setCookie = result.getResponse().getHeader("Set-Cookie");
        assertThat(setCookie).isNotNull();
        assertThat(setCookie).contains("refresh_token=");
        assertThat(setCookie).contains("HttpOnly");
        assertThat(setCookie).contains("SameSite=Lax");
        assertThat(setCookie).contains("Path=/api/v1/auth");
        assertThat(setCookie).contains("Max-Age=50400");
    }

    private static String sha256Hex(byte[] bytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(bytes);
            StringBuilder sb = new StringBuilder(64);
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
