package app.lumbral.backend.auth.controller;

import app.lumbral.backend.auth.dto.MeResponse;
import app.lumbral.backend.auth.dto.TenantSummary;
import app.lumbral.backend.auth.model.User;
import app.lumbral.backend.auth.repository.UserRepository;
import app.lumbral.backend.auth.service.AuthException;
import app.lumbral.backend.policy.Capability;
import app.lumbral.backend.policy.CapabilityResolver;
import app.lumbral.backend.policy.TenantContext;
import app.lumbral.backend.tenancy.model.Tenant;
import app.lumbral.backend.tenancy.repository.TenantRepository;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/v1")
public class MeController {

    private final UserRepository userRepository;
    private final TenantRepository tenantRepository;

    public MeController(UserRepository userRepository, TenantRepository tenantRepository) {
        this.userRepository = userRepository;
        this.tenantRepository = tenantRepository;
    }

    @GetMapping("/me")
    public MeResponse me(@AuthenticationPrincipal TenantContext ctx) {
        User user = userRepository.findById(ctx.userId())
                .orElseThrow(AuthException::invalidCredentials);

        Tenant tenant = tenantRepository.findById(ctx.tenantId())
                .orElseThrow(AuthException::noActiveMembership);

        Set<Capability> planCaps = CapabilityResolver.forPlan(ctx.tenantPlan());
        Map<String, Boolean> capabilities = new LinkedHashMap<>();
        for (Capability c : Capability.values()) {
            capabilities.put(c.name(), planCaps.contains(c));
        }

        return new MeResponse(
                new MeResponse.MeUser(user.getId(), user.getEmail()),
                new TenantSummary(tenant.getId(), tenant.getName()),
                ctx.role().name(),
                capabilities);
    }
}
