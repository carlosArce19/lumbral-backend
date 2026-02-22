package app.lumbral.backend.auth.dto;

import java.util.Map;
import java.util.UUID;

public record MeResponse(MeUser user, TenantSummary tenant, String role, Map<String, Boolean> capabilities) {

    public record MeUser(UUID id, String email) {
    }
}
