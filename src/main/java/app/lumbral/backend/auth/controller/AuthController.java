package app.lumbral.backend.auth.controller;

import app.lumbral.backend.auth.dto.AcceptInviteRequest;
import app.lumbral.backend.auth.dto.ForgotPasswordRequest;
import app.lumbral.backend.auth.dto.LoginRequest;
import app.lumbral.backend.auth.dto.LoginResponse;
import app.lumbral.backend.auth.dto.LogoutResponse;
import app.lumbral.backend.auth.dto.PasswordActionResponse;
import app.lumbral.backend.auth.dto.RefreshResponse;
import app.lumbral.backend.auth.dto.ResetPasswordRequest;
import app.lumbral.backend.auth.dto.SelectTenantRequest;
import app.lumbral.backend.auth.dto.SwitchTenantResponse;
import app.lumbral.backend.auth.service.AuthService;
import app.lumbral.backend.auth.service.AuthService.LoginResult;
import app.lumbral.backend.auth.service.InvalidTokenException;
import app.lumbral.backend.auth.service.InviteService;
import app.lumbral.backend.auth.service.PasswordResetService;
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
    private final InviteService inviteService;
    private final PasswordResetService passwordResetService;
    private final boolean cookieSecure;

    public AuthController(AuthService authService,
                          InviteService inviteService,
                          PasswordResetService passwordResetService,
                          @Value("${app.jwt.refresh-cookie-secure}") boolean cookieSecure) {
        this.authService = authService;
        this.inviteService = inviteService;
        this.passwordResetService = passwordResetService;
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

    @PostMapping("/refresh")
    public ResponseEntity<RefreshResponse> refresh(
            @CookieValue(name = "refresh_token", required = false) String rawToken) {

        if (rawToken == null) {
            throw new InvalidTokenException("Missing refresh token cookie.");
        }

        AuthService.RefreshResult result = authService.refresh(rawToken);
        RefreshResponse body = new RefreshResponse(result.accessToken(), result.accessTokenExpiresInSeconds());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, buildRefreshCookie(result.refreshToken()).toString())
                .body(body);
    }

    @PostMapping("/logout")
    public ResponseEntity<LogoutResponse> logout(
            @CookieValue(name = "refresh_token", required = false) String rawToken) {

        authService.logout(rawToken);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, buildClearRefreshCookie().toString())
                .body(new LogoutResponse(true));
    }

    @PostMapping("/invites/accept")
    public ResponseEntity<LoginResponse> acceptInvite(@Valid @RequestBody AcceptInviteRequest request) {
        LoginResult.SignedIn result = inviteService.acceptInvite(request.token(), request.password());
        return toResponse(result);
    }

    @PostMapping("/password/forgot")
    public ResponseEntity<PasswordActionResponse> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        passwordResetService.requestReset(request.email());
        return ResponseEntity.ok(new PasswordActionResponse(true));
    }

    @PostMapping("/password/reset")
    public ResponseEntity<PasswordActionResponse> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        passwordResetService.resetPassword(request.token(), request.newPassword());
        return ResponseEntity.ok(new PasswordActionResponse(true));
    }

    @PostMapping("/switch-tenant")
    public ResponseEntity<SwitchTenantResponse> switchTenant(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @Valid @RequestBody SelectTenantRequest request) {

        String bearerToken = extractBearerToken(authHeader);
        LoginResult.SignedIn signedIn = authService.switchTenant(bearerToken, request.tenantId());

        SwitchTenantResponse body = new SwitchTenantResponse(
                signedIn.tenant(), signedIn.accessToken(), signedIn.accessTokenExpiresInSeconds());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, buildRefreshCookie(signedIn.refreshToken()).toString())
                .body(body);
    }

    private ResponseEntity<LoginResponse> toResponse(LoginResult result) {
        return switch (result) {
            case LoginResult.SignedIn s -> {
                LoginResponse body = LoginResponse.signedIn(
                        s.tenant(), s.accessToken(), s.accessTokenExpiresInSeconds());

                yield ResponseEntity.ok()
                        .header(HttpHeaders.SET_COOKIE, buildRefreshCookie(s.refreshToken()).toString())
                        .body(body);
            }
            case LoginResult.TenantSelectionRequired t -> {
                LoginResponse body = LoginResponse.tenantSelection(
                        t.preAuthToken(), t.tenants());
                yield ResponseEntity.ok(body);
            }
        };
    }

    private ResponseCookie buildRefreshCookie(String value) {
        return ResponseCookie.from("refresh_token", value)
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Lax")
                .path("/api/v1/auth")
                .maxAge(50400)
                .build();
    }

    private ResponseCookie buildClearRefreshCookie() {
        return ResponseCookie.from("refresh_token", "")
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Lax")
                .path("/api/v1/auth")
                .maxAge(0)
                .build();
    }

    private static String extractBearerToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new InvalidTokenException("Missing or invalid Authorization header.");
        }
        return authHeader.substring(7);
    }
}
