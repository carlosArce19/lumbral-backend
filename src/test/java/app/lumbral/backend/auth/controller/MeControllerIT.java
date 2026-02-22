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

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ImportTestcontainers
class MeControllerIT {

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
        activeUser.setEmail("me-user-" + unique + "@example.com");
        activeUser.setPasswordHash(passwordEncoder.encode(PASSWORD));
        activeUser.setStatus(UserStatus.ACTIVE);
        activeUser = userRepository.saveAndFlush(activeUser);

        tenantA = new Tenant();
        tenantA.setName("MeTest Corp");
        tenantA.setCode("metest-" + unique);
        tenantA.setPlan(TenantPlan.BASIC);
        tenantA = tenantRepository.saveAndFlush(tenantA);
    }

    // --- 1) No Authorization header -> 401 from EntryPoint ---

    @Test
    void meWithoutToken_returns401() throws Exception {
        createMembership(activeUser, tenantA, MembershipRole.ADMIN, MembershipStatus.ACTIVE);

        mockMvc.perform(get("/api/v1/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("invalid-token")))
                .andExpect(jsonPath("$.detail").value("Authentication required."));
    }

    // --- 2) PRE_AUTH token -> 401 from Filter ---

    @Test
    void meWithPreAuthToken_returns401() throws Exception {
        createMembership(activeUser, tenantA, MembershipRole.ADMIN, MembershipStatus.ACTIVE);

        String preAuth = buildPreAuthToken(activeUser.getId());

        mockMvc.perform(get("/api/v1/me")
                        .header("Authorization", "Bearer " + preAuth))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("invalid-token")))
                .andExpect(jsonPath("$.detail").value("Access token required."));
    }

    // --- 3) Expired ACCESS token -> 401 ---

    @Test
    void meWithExpiredAccessToken_returns401() throws Exception {
        TenantMembership membership = createMembership(activeUser, tenantA,
                MembershipRole.ADMIN, MembershipStatus.ACTIVE);

        String expired = buildExpiredAccessToken(activeUser.getId(), tenantA.getId(),
                MembershipRole.ADMIN, membership.getId());

        mockMvc.perform(get("/api/v1/me")
                        .header("Authorization", "Bearer " + expired))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("invalid-token")));
    }

    // --- 4) Tampered token -> 401 ---

    @Test
    void meWithTamperedToken_returns401() throws Exception {
        createMembership(activeUser, tenantA, MembershipRole.ADMIN, MembershipStatus.ACTIVE);

        String tampered = buildTamperedToken(activeUser.getId(), tenantA.getId());

        mockMvc.perform(get("/api/v1/me")
                        .header("Authorization", "Bearer " + tampered))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("invalid-token")));
    }

    // --- 5) Disabled membership -> 403 ---

    @Test
    void meWithDisabledMembership_returns403() throws Exception {
        TenantMembership membership = createMembership(activeUser, tenantA,
                MembershipRole.ADMIN, MembershipStatus.DISABLED);

        String token = buildAccessToken(activeUser.getId(), tenantA.getId(),
                MembershipRole.ADMIN, membership.getId());

        mockMvc.perform(get("/api/v1/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.type", containsString("membership-not-active")))
                .andExpect(jsonPath("$.detail").value("Your membership is not active for this tenant."));
    }

    // --- 6) Active membership -> 200 with full response ---

    @Test
    void meWithActiveMembership_returns200() throws Exception {
        TenantMembership membership = createMembership(activeUser, tenantA,
                MembershipRole.ADMIN, MembershipStatus.ACTIVE);

        String token = buildAccessToken(activeUser.getId(), tenantA.getId(),
                MembershipRole.ADMIN, membership.getId());

        mockMvc.perform(get("/api/v1/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user.id").value(activeUser.getId().toString()))
                .andExpect(jsonPath("$.user.email").value(activeUser.getEmail()))
                .andExpect(jsonPath("$.tenant.tenantId").value(tenantA.getId().toString()))
                .andExpect(jsonPath("$.tenant.name").value("MeTest Corp"))
                .andExpect(jsonPath("$.role").value("ADMIN"))
                .andExpect(jsonPath("$.capabilities.CAP_SITE").value(true))
                .andExpect(jsonPath("$.capabilities.CAP_STORE").value(false))
                .andExpect(jsonPath("$.capabilities.CAP_SCHEDULING").value(false));
    }

    // --- 7) Login still works without token (filter skips auth endpoints) ---

    @Test
    void authLoginStillWorksWithoutToken() throws Exception {
        createMembership(activeUser, tenantA, MembershipRole.ADMIN, MembershipStatus.ACTIVE);

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson(activeUser.getEmail(), PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mode").value("SIGNED_IN"));
    }

    // --- 8) Login ignores garbage Authorization header (shouldNotFilter skips) ---

    @Test
    void authLoginIgnoresInvalidBearerHeader() throws Exception {
        createMembership(activeUser, tenantA, MembershipRole.ADMIN, MembershipStatus.ACTIVE);

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer garbage-invalid-token")
                        .content(loginJson(activeUser.getEmail(), PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mode").value("SIGNED_IN"));
    }

    // --- 9) Switch-tenant still works (permitAll, filter skipped) ---

    @Test
    void switchTenantStillPermitAll() throws Exception {
        String unique = UUID.randomUUID().toString().substring(0, 8);
        Tenant tenantB = new Tenant();
        tenantB.setName("Switch Corp");
        tenantB.setCode("switch-" + unique);
        tenantB.setPlan(TenantPlan.MID);
        tenantB = tenantRepository.saveAndFlush(tenantB);

        createMembership(activeUser, tenantA, MembershipRole.ADMIN, MembershipStatus.ACTIVE);
        createMembership(activeUser, tenantB, MembershipRole.STAFF, MembershipStatus.ACTIVE);

        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson(activeUser.getEmail(), PASSWORD)))
                .andExpect(status().isOk())
                .andReturn();

        String body = loginResult.getResponse().getContentAsString();
        String mode = extractJsonField(body, "mode");

        String accessToken;
        if ("TENANT_SELECTION_REQUIRED".equals(mode)) {
            String preAuth = extractJsonField(body, "preAuthToken");
            MvcResult selectResult = mockMvc.perform(post("/api/v1/auth/select-tenant")
                            .contentType(MediaType.APPLICATION_JSON)
                            .header("Authorization", "Bearer " + preAuth)
                            .content("{\"tenantId\":\"" + tenantA.getId() + "\"}"))
                    .andExpect(status().isOk())
                    .andReturn();
            accessToken = extractJsonField(selectResult.getResponse().getContentAsString(), "accessToken");
        } else {
            accessToken = extractJsonField(body, "accessToken");
        }

        mockMvc.perform(post("/api/v1/auth/switch-tenant")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + accessToken)
                        .content("{\"tenantId\":\"" + tenantB.getId() + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.tenant.tenantId").value(tenantB.getId().toString()));
    }

    // --- HELPERS ---

    private String buildAccessToken(UUID userId, UUID tenantId, MembershipRole role, UUID membershipId) {
        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(userId.toString())
                .claim("tenantId", tenantId.toString())
                .claim("role", role.name())
                .claim("membershipId", membershipId.toString())
                .claim("type", "ACCESS")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(900)))
                .signWith(key)
                .compact();
    }

    private String buildExpiredAccessToken(UUID userId, UUID tenantId,
                                           MembershipRole role, UUID membershipId) {
        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        Instant past = Instant.now().minusSeconds(120);
        return Jwts.builder()
                .subject(userId.toString())
                .claim("tenantId", tenantId.toString())
                .claim("role", role.name())
                .claim("membershipId", membershipId.toString())
                .claim("type", "ACCESS")
                .issuedAt(Date.from(past.minusSeconds(900)))
                .expiration(Date.from(past))
                .signWith(key)
                .compact();
    }

    private String buildPreAuthToken(UUID userId) {
        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(userId.toString())
                .claim("type", "PRE_AUTH")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(300)))
                .signWith(key)
                .compact();
    }

    private String buildTamperedToken(UUID userId, UUID tenantId) {
        SecretKey wrongKey = Keys.hmacShaKeyFor(
                "this-is-a-completely-different-secret-key!!".getBytes(StandardCharsets.UTF_8));
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(userId.toString())
                .claim("tenantId", tenantId.toString())
                .claim("role", "ADMIN")
                .claim("membershipId", UUID.randomUUID().toString())
                .claim("type", "ACCESS")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(900)))
                .signWith(wrongKey)
                .compact();
    }

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

    private static String extractJsonField(String body, String field) {
        String key = "\"" + field + "\":\"";
        int start = body.indexOf(key) + key.length();
        int end = body.indexOf("\"", start);
        return body.substring(start, end);
    }
}
