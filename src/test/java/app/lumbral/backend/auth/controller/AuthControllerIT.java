package app.lumbral.backend.auth.controller;

import app.lumbral.backend.auth.model.*;
import app.lumbral.backend.auth.repository.TenantMembershipRepository;
import app.lumbral.backend.auth.repository.UserRepository;
import app.lumbral.backend.tenancy.model.Tenant;
import app.lumbral.backend.tenancy.model.TenantPlan;
import app.lumbral.backend.tenancy.repository.TenantRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.context.ImportTestcontainers;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ImportTestcontainers
class AuthControllerIT {

    @ServiceConnection
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private TenantMembershipRepository membershipRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    private static final String PASSWORD = "test-password-123";

    private User activeUser;
    private Tenant tenantA;

    @BeforeEach
    void setUp() {
        String unique = UUID.randomUUID().toString().substring(0, 8);

        activeUser = new User();
        activeUser.setEmail("user-" + unique + "@example.com");
        activeUser.setPasswordHash(passwordEncoder.encode(PASSWORD));
        activeUser.setStatus(UserStatus.ACTIVE);
        activeUser = userRepository.saveAndFlush(activeUser);

        tenantA = new Tenant();
        tenantA.setName("Alpha Corp");
        tenantA.setCode("alpha-" + unique);
        tenantA.setPlan(TenantPlan.BASIC);
        tenantA = tenantRepository.saveAndFlush(tenantA);
    }

    // --- LOGIN TESTS ---

    @Test
    void loginSingleMembership_returnsSignedIn() throws Exception {
        createMembership(activeUser, tenantA, MembershipRole.ADMIN, MembershipStatus.ACTIVE);

        MvcResult result = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson(activeUser.getEmail(), PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mode").value("SIGNED_IN"))
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.accessTokenExpiresInSeconds").value(900))
                .andExpect(jsonPath("$.tenant.tenantId").value(tenantA.getId().toString()))
                .andExpect(jsonPath("$.tenant.name").value("Alpha Corp"))
                .andExpect(jsonPath("$.preAuthToken").doesNotExist())
                .andExpect(jsonPath("$.tenants").doesNotExist())
                .andReturn();

        assertRefreshCookiePresent(result);
    }

    @Test
    void loginMultipleMemberships_returnsTenantSelection() throws Exception {
        String unique = UUID.randomUUID().toString().substring(0, 8);
        Tenant tenantB = new Tenant();
        tenantB.setName("Beta Inc");
        tenantB.setCode("beta-" + unique);
        tenantB.setPlan(TenantPlan.MID);
        tenantB = tenantRepository.saveAndFlush(tenantB);

        createMembership(activeUser, tenantA, MembershipRole.ADMIN, MembershipStatus.ACTIVE);
        createMembership(activeUser, tenantB, MembershipRole.STAFF, MembershipStatus.ACTIVE);

        MvcResult result = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson(activeUser.getEmail(), PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mode").value("TENANT_SELECTION_REQUIRED"))
                .andExpect(jsonPath("$.preAuthToken").isNotEmpty())
                .andExpect(jsonPath("$.tenants", hasSize(2)))
                .andExpect(jsonPath("$.tenants[0].name").value("Alpha Corp"))
                .andExpect(jsonPath("$.tenants[1].name").value("Beta Inc"))
                .andExpect(jsonPath("$.accessToken").doesNotExist())
                .andExpect(jsonPath("$.tenant").doesNotExist())
                .andReturn();

        String setCookie = result.getResponse().getHeader("Set-Cookie");
        assertThat(setCookie).isNull();
    }

    @Test
    void selectTenant_returnsSignedIn() throws Exception {
        String unique = UUID.randomUUID().toString().substring(0, 8);
        Tenant tenantB = new Tenant();
        tenantB.setName("Beta Inc");
        tenantB.setCode("beta-sel-" + unique);
        tenantB.setPlan(TenantPlan.MID);
        tenantB = tenantRepository.saveAndFlush(tenantB);

        createMembership(activeUser, tenantA, MembershipRole.ADMIN, MembershipStatus.ACTIVE);
        createMembership(activeUser, tenantB, MembershipRole.STAFF, MembershipStatus.ACTIVE);

        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson(activeUser.getEmail(), PASSWORD)))
                .andExpect(status().isOk())
                .andReturn();

        String preAuthToken = extractJsonField(loginResult, "preAuthToken");

        MvcResult selectResult = mockMvc.perform(post("/api/v1/auth/select-tenant")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + preAuthToken)
                        .content("{\"tenantId\":\"" + tenantB.getId() + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mode").value("SIGNED_IN"))
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.accessTokenExpiresInSeconds").value(900))
                .andExpect(jsonPath("$.tenant.tenantId").value(tenantB.getId().toString()))
                .andExpect(jsonPath("$.tenant.name").value("Beta Inc"))
                .andReturn();

        assertRefreshCookiePresent(selectResult);
    }

    // --- LOGIN FAILURE TESTS ---

    @Test
    void loginInvalidPassword_returns401() throws Exception {
        createMembership(activeUser, tenantA, MembershipRole.ADMIN, MembershipStatus.ACTIVE);

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson(activeUser.getEmail(), "wrong-password")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("auth-failed")))
                .andExpect(jsonPath("$.detail").value("Invalid email or password."));
    }

    @Test
    void loginNonExistentEmail_returns401() throws Exception {
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson("nonexistent@example.com", PASSWORD)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("auth-failed")))
                .andExpect(jsonPath("$.detail").value("Invalid email or password."));
    }

    @Test
    void loginDisabledUser_returns401() throws Exception {
        String unique = UUID.randomUUID().toString().substring(0, 8);
        User disabledUser = new User();
        disabledUser.setEmail("disabled-" + unique + "@example.com");
        disabledUser.setPasswordHash(passwordEncoder.encode(PASSWORD));
        disabledUser.setStatus(UserStatus.DISABLED);
        disabledUser = userRepository.saveAndFlush(disabledUser);

        createMembership(disabledUser, tenantA, MembershipRole.ADMIN, MembershipStatus.ACTIVE);

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson(disabledUser.getEmail(), PASSWORD)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("auth-failed")))
                .andExpect(jsonPath("$.detail").value("Invalid email or password."));
    }

    @Test
    void loginNoActiveMemberships_returns403() throws Exception {
        createMembership(activeUser, tenantA, MembershipRole.ADMIN, MembershipStatus.DISABLED);

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson(activeUser.getEmail(), PASSWORD)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.type", containsString("no-active-membership")))
                .andExpect(jsonPath("$.detail").value("No active tenant membership."));
    }

    // --- SELECT-TENANT FAILURE TESTS ---

    @Test
    void selectTenantWrongTokenType_returns401() throws Exception {
        createMembership(activeUser, tenantA, MembershipRole.ADMIN, MembershipStatus.ACTIVE);

        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson(activeUser.getEmail(), PASSWORD)))
                .andExpect(status().isOk())
                .andReturn();

        String accessToken = extractJsonField(loginResult, "accessToken");

        mockMvc.perform(post("/api/v1/auth/select-tenant")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + accessToken)
                        .content("{\"tenantId\":\"" + tenantA.getId() + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("invalid-token")))
                .andExpect(jsonPath("$.detail").value("Expected a pre-authentication token."));
    }

    @Test
    void selectTenantMissingAuthHeader_returns401() throws Exception {
        mockMvc.perform(post("/api/v1/auth/select-tenant")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenantId\":\"" + UUID.randomUUID() + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("invalid-token")))
                .andExpect(jsonPath("$.detail").value("Missing or invalid Authorization header."));
    }

    @Test
    void selectTenantExpiredPreAuth_returns401() throws Exception {
        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        Instant past = Instant.now().minusSeconds(60);
        String expiredToken = Jwts.builder()
                .subject(activeUser.getId().toString())
                .claim("type", "PRE_AUTH")
                .issuedAt(Date.from(past.minusSeconds(300)))
                .expiration(Date.from(past))
                .signWith(key)
                .compact();

        mockMvc.perform(post("/api/v1/auth/select-tenant")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + expiredToken)
                        .content("{\"tenantId\":\"" + tenantA.getId() + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("invalid-token")));
    }

    // --- HELPERS ---

    private TenantMembership createMembership(User user, Tenant tenant,
                                              MembershipRole role, MembershipStatus status) {
        TenantMembership m = new TenantMembership();
        m.setUser(user);
        m.setTenant(tenant);
        m.setRole(role);
        m.setStatus(status);
        return membershipRepository.saveAndFlush(m);
    }

    private static String loginJson(String email, String password) {
        return "{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}";
    }

    private static String extractJsonField(MvcResult result, String field) throws Exception {
        String body = result.getResponse().getContentAsString();
        String key = "\"" + field + "\":\"";
        int start = body.indexOf(key) + key.length();
        int end = body.indexOf("\"", start);
        return body.substring(start, end);
    }

    private static void assertRefreshCookiePresent(MvcResult result) {
        String setCookie = result.getResponse().getHeader("Set-Cookie");
        assertThat(setCookie).isNotNull();
        assertThat(setCookie).contains("refresh_token=");
        assertThat(setCookie).contains("HttpOnly");
        assertThat(setCookie).contains("SameSite=Lax");
        assertThat(setCookie).contains("Path=/api/v1/auth");
        assertThat(setCookie).contains("Max-Age=50400");
        assertThat(setCookie).contains("Secure");
    }
}
