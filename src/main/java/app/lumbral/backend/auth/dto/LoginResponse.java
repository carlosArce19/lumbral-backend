package app.lumbral.backend.auth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record LoginResponse(
        String mode,
        TenantSummary tenant,
        String accessToken,
        Integer accessTokenExpiresInSeconds,
        String preAuthToken,
        List<TenantSummary> tenants
) {

    public static LoginResponse signedIn(TenantSummary tenant, String accessToken,
                                         int accessTokenExpiresInSeconds) {
        return new LoginResponse("SIGNED_IN", tenant, accessToken,
                accessTokenExpiresInSeconds, null, null);
    }

    public static LoginResponse tenantSelection(String preAuthToken,
                                                List<TenantSummary> tenants) {
        return new LoginResponse("TENANT_SELECTION_REQUIRED", null, null,
                null, preAuthToken, tenants);
    }
}
