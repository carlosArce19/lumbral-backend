package app.lumbral.backend.auth.controller;

import app.lumbral.backend.auth.dto.LoginRequest;
import app.lumbral.backend.auth.dto.LoginResponse;
import app.lumbral.backend.auth.dto.SelectTenantRequest;
import app.lumbral.backend.auth.service.AuthService;
import app.lumbral.backend.auth.service.AuthService.LoginResult;
import app.lumbral.backend.auth.service.InvalidTokenException;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;
    private final boolean cookieSecure;

    public AuthController(AuthService authService,
                          @Value("${app.jwt.refresh-cookie-secure}") boolean cookieSecure) {
        this.authService = authService;
        this.cookieSecure = cookieSecure;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        LoginResult result = authService.login(request.email(), request.password());
        return toResponse(result);
    }

    @PostMapping("/select-tenant")
    public ResponseEntity<LoginResponse> selectTenant(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @Valid @RequestBody SelectTenantRequest request) {

        String bearerToken = extractBearerToken(authHeader);
        LoginResult.SignedIn result = authService.selectTenant(bearerToken, request.tenantId());
        return toResponse(result);
    }

    private ResponseEntity<LoginResponse> toResponse(LoginResult result) {
        return switch (result) {
            case LoginResult.SignedIn s -> {
                LoginResponse body = LoginResponse.signedIn(
                        s.tenant(), s.accessToken(), s.accessTokenExpiresInSeconds());

                ResponseCookie cookie = ResponseCookie
                        .from("refresh_token", s.refreshToken())
                        .httpOnly(true)
                        .secure(cookieSecure)
                        .sameSite("Lax")
                        .path("/api/v1/auth")
                        .maxAge(50400)
                        .build();

                yield ResponseEntity.ok()
                        .header(HttpHeaders.SET_COOKIE, cookie.toString())
                        .body(body);
            }
            case LoginResult.TenantSelectionRequired t -> {
                LoginResponse body = LoginResponse.tenantSelection(
                        t.preAuthToken(), t.tenants());
                yield ResponseEntity.ok(body);
            }
        };
    }

    private static String extractBearerToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new InvalidTokenException("Missing or invalid Authorization header.");
        }
        return authHeader.substring(7);
    }
}
