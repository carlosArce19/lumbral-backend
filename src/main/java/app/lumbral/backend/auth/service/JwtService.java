package app.lumbral.backend.auth.service;

import app.lumbral.backend.auth.model.MembershipRole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {

    private final SecretKey key;
    private final Duration accessTokenTtl;
    private final Duration preAuthTokenTtl;

    public JwtService(@Value("${app.jwt.secret}") String secret,
                      @Value("${app.jwt.access-token-ttl}") Duration accessTokenTtl,
                      @Value("${app.jwt.pre-auth-token-ttl}") Duration preAuthTokenTtl) {
        byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
        if (secretBytes.length < 32) {
            throw new IllegalStateException(
                    "JWT secret must be at least 32 bytes long, got " + secretBytes.length);
        }
        this.key = Keys.hmacShaKeyFor(secretBytes);
        this.accessTokenTtl = accessTokenTtl;
        this.preAuthTokenTtl = preAuthTokenTtl;
    }

    public String generateAccessToken(UUID userId, UUID tenantId,
                                       MembershipRole role, UUID membershipId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(userId.toString())
                .claim("tenantId", tenantId.toString())
                .claim("role", role.name())
                .claim("membershipId", membershipId.toString())
                .claim("type", TokenType.ACCESS.name())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(accessTokenTtl)))
                .signWith(key)
                .compact();
    }

    public String generatePreAuthToken(UUID userId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(userId.toString())
                .claim("type", TokenType.PRE_AUTH.name())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(preAuthTokenTtl)))
                .signWith(key)
                .compact();
    }

    public Claims parseAndValidate(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidTokenException("Invalid or expired JWT token", e);
        }
    }

    public UUID getUserId(Claims claims) {
        return UUID.fromString(claims.getSubject());
    }

    public UUID getTenantId(Claims claims) {
        String tenantId = claims.get("tenantId", String.class);
        if (tenantId == null) {
            throw new InvalidTokenException("Token does not contain tenantId claim");
        }
        return UUID.fromString(tenantId);
    }

    public MembershipRole getRole(Claims claims) {
        String role = claims.get("role", String.class);
        if (role == null) {
            throw new InvalidTokenException("Token does not contain role claim");
        }
        try {
            return MembershipRole.valueOf(role);
        } catch (IllegalArgumentException e) {
            throw new InvalidTokenException("Unknown role: " + role, e);
        }
    }

    public UUID getMembershipId(Claims claims) {
        String membershipId = claims.get("membershipId", String.class);
        if (membershipId == null) {
            throw new InvalidTokenException("Token does not contain membershipId claim");
        }
        return UUID.fromString(membershipId);
    }

    public TokenType getTokenType(Claims claims) {
        String type = claims.get("type", String.class);
        if (type == null) {
            throw new InvalidTokenException("Token does not contain type claim");
        }
        try {
            return TokenType.valueOf(type);
        } catch (IllegalArgumentException e) {
            throw new InvalidTokenException("Unknown token type: " + type, e);
        }
    }
}
