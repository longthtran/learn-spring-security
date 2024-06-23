package org.example.config.security;

import lombok.AllArgsConstructor;
import org.example.entity.UserRole;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.TestingAuthenticationProvider;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@Profile("dev")
@AllArgsConstructor
public class DevAuthenticationProvider extends TestingAuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String principal = (String) authentication.getPrincipal();
        String credentials = (String) authentication.getCredentials();

        if ("admin".equals(principal) && "12345".equals(credentials)) {
            return new TestingAuthenticationToken(principal, credentials, List.of(new SimpleGrantedAuthority("ROLE_" + UserRole.ADMIN.name())));
        }
        return null;
    }

}
