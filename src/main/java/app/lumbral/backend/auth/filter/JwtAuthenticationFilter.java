package app.lumbral.backend.auth.filter;

import app.lumbral.backend.auth.model.MembershipStatus;
import app.lumbral.backend.auth.model.TenantMembership;
import app.lumbral.backend.auth.repository.TenantMembershipRepository;
import app.lumbral.backend.auth.service.InvalidTokenException;
import app.lumbral.backend.auth.service.JwtService;
import app.lumbral.backend.auth.service.TokenType;
import app.lumbral.backend.common.errors.ApiError;
import app.lumbral.backend.policy.TenantContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;
import java.util.UUID;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String PROBLEM_BASE = ApiError.PROBLEM_BASE;
    private static final String TRACE_ID_MDC = "traceId";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final TenantMembershipRepository membershipRepository;
    private final ObjectMapper objectMapper;

    public JwtAuthenticationFilter(JwtService jwtService,
                                   TenantMembershipRepository membershipRepository,
                                   ObjectMapper objectMapper) {
        this.jwtService = jwtService;
        this.membershipRepository = membershipRepository;
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getRequestURI().startsWith("/api/v1/auth/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(BEARER_PREFIX.length()).trim();
        if (token.isEmpty()) {
            filterChain.doFilter(request, response);
            return;
        }

        String path = request.getRequestURI();

        Claims claims;
        try {
            claims = jwtService.parseAndValidate(token);
        } catch (InvalidTokenException ex) {
            writeError(response, 401, "invalid-token", "Invalid token",
                    ex.getMessage(), path);
            return;
        }

        TokenType type;
        try {
            type = jwtService.getTokenType(claims);
        } catch (InvalidTokenException ex) {
            writeError(response, 401, "invalid-token", "Invalid token",
                    ex.getMessage(), path);
            return;
        }

        if (type != TokenType.ACCESS) {
            writeError(response, 401, "invalid-token", "Invalid token",
                    "Access token required.", path);
            return;
        }

        UUID userId;
        UUID tenantId;
        try {
            userId = jwtService.getUserId(claims);
            tenantId = jwtService.getTenantId(claims);
        } catch (InvalidTokenException ex) {
            writeError(response, 401, "invalid-token", "Invalid token",
                    ex.getMessage(), path);
            return;
        }

        Optional<TenantMembership> membershipOpt =
                membershipRepository.findWithTenantByUserIdAndTenantId(userId, tenantId);

        if (membershipOpt.isEmpty()) {
            writeError(response, 401, "invalid-token", "Invalid token",
                    "Token references unknown membership.", path);
            return;
        }

        TenantMembership membership = membershipOpt.get();

        if (membership.getStatus() != MembershipStatus.ACTIVE) {
            writeError(response, 403, "membership-not-active", "Membership not active",
                    "Your membership is not active for this tenant.", path);
            return;
        }

        TenantContext ctx = new TenantContext(
                tenantId,
                userId,
                membership.getRole(),
                membership.getId(),
                membership.getStatus(),
                membership.getTenant().getPlan());

        SecurityContextHolder.getContext().setAuthentication(new TenantAuthentication(ctx));

        filterChain.doFilter(request, response);
    }

    private void writeError(HttpServletResponse response, int status, String typeSuffix,
                            String title, String detail, String path) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        ApiError body = ApiError.of(
                PROBLEM_BASE + typeSuffix,
                title,
                status,
                detail,
                path,
                getTraceId());

        objectMapper.writeValue(response.getOutputStream(), body);
    }

    private static String getTraceId() {
        String traceId = MDC.get(TRACE_ID_MDC);
        return traceId != null ? traceId : "";
    }
}
