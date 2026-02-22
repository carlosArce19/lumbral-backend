package app.lumbral.backend.auth.service;

import app.lumbral.backend.auth.dto.TenantSummary;
import app.lumbral.backend.auth.model.MembershipStatus;
import app.lumbral.backend.auth.model.TenantMembership;
import app.lumbral.backend.auth.model.User;
import app.lumbral.backend.auth.model.UserStatus;
import app.lumbral.backend.auth.repository.TenantMembershipRepository;
import app.lumbral.backend.auth.repository.UserRepository;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final TenantMembershipRepository membershipRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final int accessTokenExpiresInSeconds;

    public AuthService(UserRepository userRepository,
                       TenantMembershipRepository membershipRepository,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService,
                       RefreshTokenService refreshTokenService,
                       @Value("${app.jwt.access-token-ttl}") Duration accessTokenTtl) {
        this.userRepository = userRepository;
        this.membershipRepository = membershipRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.accessTokenExpiresInSeconds = (int) accessTokenTtl.toSeconds();
    }

    public sealed interface LoginResult {
        record SignedIn(String accessToken, int accessTokenExpiresInSeconds,
                        String refreshToken, TenantSummary tenant) implements LoginResult {
        }

        record TenantSelectionRequired(String preAuthToken,
                                       List<TenantSummary> tenants) implements LoginResult {
        }
    }

    @Transactional
    public LoginResult login(String email, String password) {
        String normalized = email.trim().toLowerCase();

        User user = userRepository.findByEmail(normalized)
                .orElseThrow(AuthException::invalidCredentials);

        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw AuthException.invalidCredentials();
        }

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw AuthException.invalidCredentials();
        }

        List<TenantMembership> memberships =
                membershipRepository.findAllByUser_IdAndStatus(user.getId(), MembershipStatus.ACTIVE);

        if (memberships.isEmpty()) {
            throw AuthException.noActiveMembership();
        }

        if (memberships.size() == 1) {
            return buildSignedIn(user, memberships.getFirst());
        }

        List<TenantSummary> tenants = memberships.stream()
                .map(m -> new TenantSummary(m.getTenant().getId(), m.getTenant().getName()))
                .sorted(Comparator.comparing(TenantSummary::name))
                .toList();

        String preAuthToken = jwtService.generatePreAuthToken(user.getId());
        return new LoginResult.TenantSelectionRequired(preAuthToken, tenants);
    }

    @Transactional
    public LoginResult.SignedIn selectTenant(String bearerToken, UUID tenantId) {
        Claims claims = jwtService.parseAndValidate(bearerToken);

        TokenType type = jwtService.getTokenType(claims);
        if (type != TokenType.PRE_AUTH) {
            throw new InvalidTokenException("Expected a pre-authentication token.");
        }

        UUID userId = jwtService.getUserId(claims);

        User user = userRepository.findById(userId)
                .orElseThrow(AuthException::invalidCredentials);

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw AuthException.invalidCredentials();
        }

        TenantMembership membership = membershipRepository
                .findByUser_IdAndTenant_Id(userId, tenantId)
                .orElseThrow(AuthException::membershipNotFound);

        if (membership.getStatus() != MembershipStatus.ACTIVE) {
            throw AuthException.membershipNotFound();
        }

        return buildSignedIn(user, membership);
    }

    private LoginResult.SignedIn buildSignedIn(User user, TenantMembership membership) {
        String accessToken = jwtService.generateAccessToken(
                user.getId(),
                membership.getTenant().getId(),
                membership.getRole(),
                membership.getId());

        String refreshToken = refreshTokenService.createRefreshToken(user, membership.getTenant());

        TenantSummary tenant = new TenantSummary(
                membership.getTenant().getId(),
                membership.getTenant().getName());

        return new LoginResult.SignedIn(accessToken, accessTokenExpiresInSeconds,
                refreshToken, tenant);
    }
}
