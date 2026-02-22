package app.lumbral.backend.auth.service;

import app.lumbral.backend.auth.model.*;
import app.lumbral.backend.auth.repository.InviteRepository;
import app.lumbral.backend.auth.repository.TenantMembershipRepository;
import app.lumbral.backend.auth.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

@Service
public class InviteService {

    private final InviteRepository inviteRepository;
    private final UserRepository userRepository;
    private final TenantMembershipRepository membershipRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthService authService;

    public InviteService(InviteRepository inviteRepository,
                         UserRepository userRepository,
                         TenantMembershipRepository membershipRepository,
                         PasswordEncoder passwordEncoder,
                         AuthService authService) {
        this.inviteRepository = inviteRepository;
        this.userRepository = userRepository;
        this.membershipRepository = membershipRepository;
        this.passwordEncoder = passwordEncoder;
        this.authService = authService;
    }

    @Transactional
    public AuthService.LoginResult.SignedIn acceptInvite(String rawToken, String password) {
        byte[] rawBytes;
        try {
            rawBytes = Base64.getUrlDecoder().decode(rawToken);
        } catch (IllegalArgumentException e) {
            throw new InvalidTokenException("Invalid invite token.");
        }

        String tokenHash = sha256Hex(rawBytes);

        Invite invite = inviteRepository.findWithTenantByTokenHash(tokenHash)
                .orElseThrow(() -> new InvalidTokenException("Invalid invite token."));

        if (invite.getAcceptedAt() != null) {
            throw AuthException.inviteAlreadyAccepted();
        }

        if (invite.getExpiresAt().isBefore(Instant.now())) {
            throw new InvalidTokenException("Invite token has expired.");
        }

        String email = invite.getEmail().trim().toLowerCase();

        Optional<User> existingUser = userRepository.findByEmail(email);
        User user;

        if (existingUser.isEmpty()) {
            user = new User();
            user.setEmail(email);
            user.setPasswordHash(passwordEncoder.encode(password));
            user.setStatus(UserStatus.ACTIVE);
            user = userRepository.saveAndFlush(user);
        } else {
            user = existingUser.get();
            if (user.getStatus() != UserStatus.ACTIVE) {
                throw AuthException.invalidCredentials();
            }
            if (!passwordEncoder.matches(password, user.getPasswordHash())) {
                throw AuthException.invalidCredentials();
            }
        }

        Optional<TenantMembership> existingMembership =
                membershipRepository.findByUser_IdAndTenant_Id(user.getId(), invite.getTenant().getId());

        TenantMembership membership;

        if (existingMembership.isEmpty()) {
            membership = new TenantMembership();
            membership.setUser(user);
            membership.setTenant(invite.getTenant());
            membership.setRole(invite.getRole());
            membership.setStatus(MembershipStatus.ACTIVE);
            membership = membershipRepository.saveAndFlush(membership);
        } else {
            membership = existingMembership.get();
            if (membership.getStatus() == MembershipStatus.DISABLED) {
                throw AuthException.noActiveMembership();
            }
            if (membership.getStatus() == MembershipStatus.INVITED) {
                membership.setStatus(MembershipStatus.ACTIVE);
                membership = membershipRepository.saveAndFlush(membership);
            }
        }

        invite.setAcceptedAt(Instant.now());
        inviteRepository.save(invite);

        return authService.issueSignedIn(user, membership);
    }

    private static String sha256Hex(byte[] bytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(bytes);
            StringBuilder sb = new StringBuilder(64);
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
