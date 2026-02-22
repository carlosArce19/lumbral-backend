package app.lumbral.backend.auth.dto;

public record SwitchTenantResponse(
        TenantSummary tenant,
        String accessToken,
        int accessTokenExpiresInSeconds
) {
}
