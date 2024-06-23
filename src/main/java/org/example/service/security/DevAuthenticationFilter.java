package org.example.service.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

import static org.example.config.security.WebSecurityConfig.AUTH_URL;

@AllArgsConstructor
@Slf4j
public class DevAuthenticationFilter extends OncePerRequestFilter {

    private static final List<String> EXCLUDE_URLS = List.of(AUTH_URL);

    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    private final AuthenticationManager authenticationManager;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.debug("Start dev authentication filter");
        String username = request.getHeader("username");
        String password = request.getHeader("password");
        if (StringUtils.isBlank(username) || StringUtils.isBlank(password)) {
            log.debug("Cant find username and password params");
            filterChain.doFilter(request, response);
            return;
        }

        try {
            log.debug("Successful authenticate with dev user!");
            Authentication authentication = this.authenticationManager.authenticate(new TestingAuthenticationToken(username, password));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            log.warn("Dev authentication provider failed, continue to dao authentication");
            filterChain.doFilter(request, response);
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return EXCLUDE_URLS.stream().anyMatch(p -> antPathMatcher.match(p, path));
    }
}
