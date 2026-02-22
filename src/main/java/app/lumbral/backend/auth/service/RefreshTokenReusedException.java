package app.lumbral.backend.auth.service;

import java.util.UUID;

public class RefreshTokenReusedException extends RuntimeException {

    private final UUID userId;
    private final UUID tenantId;

    public RefreshTokenReusedException(UUID userId, UUID tenantId) {
        super("Refresh token reuse detected for user " + userId + " in tenant " + tenantId);
        this.userId = userId;
        this.tenantId = tenantId;
    }

    public UUID getUserId() {
        return userId;
    }

    public UUID getTenantId() {
        return tenantId;
    }
}
