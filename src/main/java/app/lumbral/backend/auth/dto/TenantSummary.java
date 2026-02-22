package app.lumbral.backend.auth.dto;

import java.util.UUID;

public record TenantSummary(UUID tenantId, String name) {
}
