package app.lumbral.backend.auth.controller;

import app.lumbral.backend.auth.model.*;
import app.lumbral.backend.auth.repository.RefreshTokenRepository;
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
import jakarta.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ImportTestcontainers
class AuthSessionIT {

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
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    private static final String PASSWORD = "session-test-pw-123";

    private User activeUser;
    private Tenant tenantA;

    @BeforeEach
    void setUp() {
        String unique = UUID.randomUUID().toString().substring(0, 8);

        activeUser = new User();
        activeUser.setEmail("session-" + unique + "@example.com");
        activeUser.setPasswordHash(passwordEncoder.encode(PASSWORD));
        activeUser.setStatus(UserStatus.ACTIVE);
        activeUser = userRepository.saveAndFlush(activeUser);

        tenantA = new Tenant();
        tenantA.setName("Session Alpha");
        tenantA.setCode("sa-" + unique);
        tenantA.setPlan(TenantPlan.BASIC);
        tenantA = tenantRepository.saveAndFlush(tenantA);
    }

    // ===== REFRESH TESTS (5) =====

    @Test
    void refreshSuccess_rotatesAndReturnsNewAccessToken() throws Exception {
        createMembership(activeUser, tenantA, MembershipRole.ADMIN, MembershipStatus.ACTIVE);

        String originalCookie = loginAndExtractRefreshCookieValue(activeUser.getEmail(), PASSWORD);

        MvcResult result = mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(new Cookie("refresh_token", originalCookie)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.accessTokenExpiresInSeconds").value(900))
                .andReturn();

        String setCookie = result.getResponse().getHeader("Set-Cookie");
        assertCookieSet(setCookie);

        String newCookieValue = extractRefreshCookieValue(setCookie);
        assertThat(newCookieValue).isNotEqualTo(originalCookie);
    }

    @Test
    void refreshReuseDetection_returns401AndClearsCookie() throws Exception {
        createMembership(activeUser, tenantA, MembershipRole.ADMIN, MembershipStatus.ACTIVE);

        String originalCookie = loginAndExtractRefreshCookieValue(activeUser.getEmail(), PASSWORD);

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(new Cookie("refresh_token", originalCookie)))
                .andExpect(status().isOk());

        MvcResult reuseResult = mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(new Cookie("refresh_token", originalCookie)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("token-reuse-detected")))
                .andExpect(jsonPath("$.detail").value("Refresh token reuse detected."))
                .andReturn();

        assertCookieCleared(reuseResult.getResponse().getHeader("Set-Cookie"));

        List<RefreshToken> tokens = refreshTokenRepository
                .findAllByUser_IdAndTenant_Id(activeUser.getId(), tenantA.getId());
        assertThat(tokens).isNotEmpty();
        assertThat(tokens).allMatch(t -> t.getRevokedAt() != null);
    }

    @Test
    void refreshExpiredToken_returns401AndClearsCookie() throws Exception {
        createMembership(activeUser, tenantA, MembershipRole.ADMIN, MembershipStatus.ACTIVE);

        String cookie = loginAndExtractRefreshCookieValue(activeUser.getEmail(), PASSWORD);

        List<RefreshToken> tokens = refreshTokenRepository
                .findAllByUser_IdAndTenant_Id(activeUser.getId(), tenantA.getId());
        for (RefreshToken t : tokens) {
            if (t.getRevokedAt() == null) {
                t.setExpiresAt(Instant.now().minusSeconds(60));
                refreshTokenRepository.saveAndFlush(t);
            }
        }

        MvcResult result = mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(new Cookie("refresh_token", cookie)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("invalid-token")))
                .andReturn();

        assertCookieCleared(result.getResponse().getHeader("Set-Cookie"));
    }

    @Test
    void refreshMissingCookie_returns401() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/auth/refresh"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("invalid-token")))
                .andExpect(jsonPath("$.detail").value("Missing refresh token cookie."))
                .andReturn();

        assertCookieCleared(result.getResponse().getHeader("Set-Cookie"));
    }

    @Test
    void refreshInvalidFormat_returns401() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(new Cookie("refresh_token", "not-valid!!!")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("invalid-token")))
                .andReturn();

        assertCookieCleared(result.getResponse().getHeader("Set-Cookie"));
    }

    // ===== LOGOUT TESTS (3) =====

    @Test
    void logoutSuccess_revokesAndClearsCookie() throws Exception {
        createMembership(activeUser, tenantA, MembershipRole.ADMIN, MembershipStatus.ACTIVE);

        String cookie = loginAndExtractRefreshCookieValue(activeUser.getEmail(), PASSWORD);

        MvcResult result = mockMvc.perform(post("/api/v1/auth/logout")
                        .cookie(new Cookie("refresh_token", cookie)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ok").value(true))
                .andReturn();

        assertCookieCleared(result.getResponse().getHeader("Set-Cookie"));

        List<RefreshToken> tokens = refreshTokenRepository
                .findAllByUser_IdAndTenant_Id(activeUser.getId(), tenantA.getId());
        assertThat(tokens).isNotEmpty();
        assertThat(tokens).allMatch(t -> t.getRevokedAt() != null);
    }

    @Test
    void logoutMissingCookie_returnsOkAndClearsCookie() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/auth/logout"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ok").value(true))
                .andReturn();

        assertCookieCleared(result.getResponse().getHeader("Set-Cookie"));
    }

    @Test
    void logoutInvalidCookie_returnsOkAndClearsCookie() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/auth/logout")
                        .cookie(new Cookie("refresh_token", "garbage")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ok").value(true))
                .andReturn();

        assertCookieCleared(result.getResponse().getHeader("Set-Cookie"));
    }

    // ===== SWITCH-TENANT TESTS (5) =====

    @Test
    void switchTenantSuccess_issuesNewTokensAndCookie() throws Exception {
        String unique = UUID.randomUUID().toString().substring(0, 8);

        Tenant tenantB = new Tenant();
        tenantB.setName("Session Beta");
        tenantB.setCode("sb-" + unique);
        tenantB.setPlan(TenantPlan.MID);
        tenantB = tenantRepository.saveAndFlush(tenantB);

        createMembership(activeUser, tenantA, MembershipRole.ADMIN, MembershipStatus.ACTIVE);
        createMembership(activeUser, tenantB, MembershipRole.STAFF, MembershipStatus.ACTIVE);

        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson(activeUser.getEmail(), PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mode").value("TENANT_SELECTION_REQUIRED"))
                .andReturn();

        String preAuthToken = extractJsonField(loginResult, "preAuthToken");

        MvcResult selectResult = mockMvc.perform(post("/api/v1/auth/select-tenant")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + preAuthToken)
                        .content("{\"tenantId\":\"" + tenantA.getId() + "\"}"))
                .andExpect(status().isOk())
                .andReturn();

        String accessTokenA = extractJsonField(selectResult, "accessToken");

        MvcResult switchResult = mockMvc.perform(post("/api/v1/auth/switch-tenant")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + accessTokenA)
                        .content("{\"tenantId\":\"" + tenantB.getId() + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenant.tenantId").value(tenantB.getId().toString()))
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.accessTokenExpiresInSeconds").value(900))
                .andReturn();

        assertCookieSet(switchResult.getResponse().getHeader("Set-Cookie"));

        List<RefreshToken> oldTenantTokens = refreshTokenRepository
                .findAllByUser_IdAndTenant_Id(activeUser.getId(), tenantA.getId());
        assertThat(oldTenantTokens).isNotEmpty();
        assertThat(oldTenantTokens).allMatch(t -> t.getRevokedAt() != null);

        List<RefreshToken> newTenantTokens = refreshTokenRepository
                .findAllByUser_IdAndTenant_Id(activeUser.getId(), tenantB.getId());
        assertThat(newTenantTokens).isNotEmpty();
        assertThat(newTenantTokens).anyMatch(t -> t.getRevokedAt() == null && t.getExpiresAt().isAfter(Instant.now()));
    }

    @Test
    void switchTenantMembershipNotFound_returns403() throws Exception {
        createMembership(activeUser, tenantA, MembershipRole.ADMIN, MembershipStatus.ACTIVE);

        String unique = UUID.randomUUID().toString().substring(0, 8);
        Tenant tenantC = new Tenant();
        tenantC.setName("No Membership Tenant");
        tenantC.setCode("nm-" + unique);
        tenantC.setPlan(TenantPlan.BASIC);
        tenantC = tenantRepository.saveAndFlush(tenantC);

        MvcResult loginResult = loginSingleMembership(activeUser.getEmail(), PASSWORD);
        String accessToken = extractJsonField(loginResult, "accessToken");

        MvcResult result = mockMvc.perform(post("/api/v1/auth/switch-tenant")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + accessToken)
                        .content("{\"tenantId\":\"" + tenantC.getId() + "\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.type", containsString("membership-not-found")))
                .andReturn();

        assertThat(result.getResponse().getHeader("Set-Cookie")).isNull();
    }

    @Test
    void switchTenantDisabledMembership_returns403() throws Exception {
        String unique = UUID.randomUUID().toString().substring(0, 8);

        Tenant tenantB = new Tenant();
        tenantB.setName("Disabled Membership Tenant");
        tenantB.setCode("dm-" + unique);
        tenantB.setPlan(TenantPlan.BASIC);
        tenantB = tenantRepository.saveAndFlush(tenantB);

        createMembership(activeUser, tenantA, MembershipRole.ADMIN, MembershipStatus.ACTIVE);
        createMembership(activeUser, tenantB, MembershipRole.STAFF, MembershipStatus.DISABLED);

        MvcResult loginResult = loginSingleMembership(activeUser.getEmail(), PASSWORD);
        String accessToken = extractJsonField(loginResult, "accessToken");

        MvcResult result = mockMvc.perform(post("/api/v1/auth/switch-tenant")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + accessToken)
                        .content("{\"tenantId\":\"" + tenantB.getId() + "\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.type", containsString("membership-not-found")))
                .andReturn();

        assertThat(result.getResponse().getHeader("Set-Cookie")).isNull();
    }

    @Test
    void switchTenantMissingAuthHeader_returns401() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/auth/switch-tenant")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenantId\":\"" + UUID.randomUUID() + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("invalid-token")))
                .andReturn();

        assertThat(result.getResponse().getHeader("Set-Cookie")).isNull();
    }

    @Test
    void switchTenantExpiredAccessToken_returns401() throws Exception {
        createMembership(activeUser, tenantA, MembershipRole.ADMIN, MembershipStatus.ACTIVE);

        String unique = UUID.randomUUID().toString().substring(0, 8);
        Tenant tenantB = new Tenant();
        tenantB.setName("Target Tenant");
        tenantB.setCode("tt-" + unique);
        tenantB.setPlan(TenantPlan.BASIC);
        tenantB = tenantRepository.saveAndFlush(tenantB);
        createMembership(activeUser, tenantB, MembershipRole.STAFF, MembershipStatus.ACTIVE);

        String expiredToken = buildExpiredAccessToken(
                activeUser.getId(), tenantA.getId(), MembershipRole.ADMIN,
                membershipRepository.findByUser_IdAndTenant_Id(activeUser.getId(), tenantA.getId())
                        .orElseThrow().getId());

        MvcResult result = mockMvc.perform(post("/api/v1/auth/switch-tenant")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + expiredToken)
                        .content("{\"tenantId\":\"" + tenantB.getId() + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type", containsString("invalid-token")))
                .andReturn();

        assertThat(result.getResponse().getHeader("Set-Cookie")).isNull();
    }

    // ===== HELPERS =====

    private TenantMembership createMembership(User user, Tenant tenant,
                                              MembershipRole role, MembershipStatus status) {
        TenantMembership m = new TenantMembership();
        m.setUser(user);
        m.setTenant(tenant);
        m.setRole(role);
        m.setStatus(status);
        return membershipRepository.saveAndFlush(m);
    }

    private String loginAndExtractRefreshCookieValue(String email, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson(email, password)))
                .andExpect(status().isOk())
                .andReturn();

        String setCookie = result.getResponse().getHeader("Set-Cookie");
        assertThat(setCookie).isNotNull();
        return extractRefreshCookieValue(setCookie);
    }

    private MvcResult loginSingleMembership(String email, String password) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson(email, password)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mode").value("SIGNED_IN"))
                .andReturn();
    }

    private String buildExpiredAccessToken(UUID userId, UUID tenantId, MembershipRole role, UUID membershipId) {
        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        Instant past = Instant.now().minusSeconds(60);
        return Jwts.builder()
                .subject(userId.toString())
                .claim("tenantId", tenantId.toString())
                .claim("role", role.name())
                .claim("membershipId", membershipId.toString())
                .claim("type", "ACCESS")
                .issuedAt(Date.from(past.minusSeconds(300)))
                .expiration(Date.from(past))
                .signWith(key)
                .compact();
    }

    private static String extractRefreshCookieValue(String setCookieHeader) {
        for (String part : setCookieHeader.split(";")) {
            String trimmed = part.trim();
            if (trimmed.startsWith("refresh_token=")) {
                return trimmed.substring("refresh_token=".length());
            }
        }
        throw new AssertionError("refresh_token not found in Set-Cookie header: " + setCookieHeader);
    }

    private static String extractJsonField(MvcResult result, String field) throws Exception {
        String body = result.getResponse().getContentAsString();
        String key = "\"" + field + "\":\"";
        int start = body.indexOf(key) + key.length();
        int end = body.indexOf("\"", start);
        return body.substring(start, end);
    }

    private static String loginJson(String email, String password) {
        return "{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}";
    }

    private static void assertCookieSet(String setCookie) {
        assertThat(setCookie).isNotNull();
        assertThat(setCookie).contains("refresh_token=");
        assertThat(setCookie).contains("HttpOnly");
        assertThat(setCookie).contains("SameSite=Lax");
        assertThat(setCookie).contains("Path=/api/v1/auth");
        assertThat(setCookie).contains("Max-Age=50400");
    }

    private static void assertCookieCleared(String setCookie) {
        assertThat(setCookie).isNotNull();
        assertThat(setCookie).contains("refresh_token=");
        assertThat(setCookie).contains("Max-Age=0");
        assertThat(setCookie).contains("HttpOnly");
        assertThat(setCookie).contains("SameSite=Lax");
        assertThat(setCookie).contains("Path=/api/v1/auth");
    }
}
