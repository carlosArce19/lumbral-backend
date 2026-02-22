package app.lumbral.backend.auth.filter;

import app.lumbral.backend.policy.TenantContext;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

public class TenantAuthentication extends AbstractAuthenticationToken {

    private final TenantContext tenantContext;

    public TenantAuthentication(TenantContext tenantContext) {
        super(List.of(new SimpleGrantedAuthority("ROLE_" + tenantContext.role().name())));
        this.tenantContext = tenantContext;
        setAuthenticated(true);
    }

    @Override
    public Object getPrincipal() {
        return tenantContext;
    }

    @Override
    public Object getCredentials() {
        return null;
    }
}
