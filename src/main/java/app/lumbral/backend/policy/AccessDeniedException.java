package app.lumbral.backend.policy;

public class AccessDeniedException extends RuntimeException {

    public enum Reason {
        MEMBERSHIP_NOT_ACTIVE,
        ACTION_NOT_PERMITTED,
        CAPABILITY_MISSING
    }

    private final Reason reason;
    private final Action action;

    public AccessDeniedException(Reason reason, Action action) {
        super(reason.name() + ": " + action.name());
        this.reason = reason;
        this.action = action;
    }

    public Reason getReason() {
        return reason;
    }

    public Action getAction() {
        return action;
    }
}
