package app.lumbral.backend.auth.dto;

import jakarta.validation.constraints.NotBlank;

public record AcceptInviteRequest(
        @NotBlank String token,
        @NotBlank String password
) {
}
