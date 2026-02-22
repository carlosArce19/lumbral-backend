package app.lumbral.backend.auth.dto;

public record RefreshResponse(String accessToken, int accessTokenExpiresInSeconds) {
}
