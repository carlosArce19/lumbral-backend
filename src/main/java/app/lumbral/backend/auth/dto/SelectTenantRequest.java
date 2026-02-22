package app.lumbral.backend.auth.dto;

import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record SelectTenantRequest(
        @NotNull UUID tenantId
) {
}
