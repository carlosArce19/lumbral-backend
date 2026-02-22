package app.lumbral.backend.auth.service;

import lombok.Getter;

@Getter
public class AuthException extends RuntimeException {

    private final String problemType;
    private final String title;
    private final int httpStatus;

    private AuthException(String problemType, String title, int httpStatus, String detail) {
        super(detail);
        this.problemType = problemType;
        this.title = title;
        this.httpStatus = httpStatus;
    }

    public static AuthException invalidCredentials() {
        return new AuthException("auth-failed", "Authentication failed",
                401, "Invalid email or password.");
    }

    public static AuthException noActiveMembership() {
        return new AuthException("no-active-membership", "No active membership",
                403, "No active tenant membership.");
    }

    public static AuthException membershipNotFound() {
        return new AuthException("membership-not-found", "Membership not found",
                403, "User is not an active member of the requested tenant.");
    }

    public static AuthException inviteAlreadyAccepted() {
        return new AuthException("invite-already-accepted", "Invite already accepted",
                409, "This invite has already been accepted.");
    }
}
