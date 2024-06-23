package org.example.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.entity.UserRole;
import org.example.service.security.CustomAuthenticationFilter;
import org.example.service.security.DevAuthenticationFilter;
import org.example.service.security.JwtAuthenticationFilter;
import org.example.service.security.JwtTokenProvider;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Arrays;

import static org.springframework.security.config.Customizer.withDefaults;

// https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@AllArgsConstructor
@Slf4j
public class WebSecurityConfig {

    public static final String AUTH_URL = "/api/auth";

    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    private final CustomAccessDeniedHandler customAccessDeniedHandler;

    private final UserDetailsService userDetailsService;

    private final ObjectMapper objectMapper;

    private final Environment environment;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager, JwtAuthenticationFilter jwtAuthenticationFilter, JwtTokenProvider jwtTokenProvider) throws Exception {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManager, jwtTokenProvider, objectMapper);
        customAuthenticationFilter.setFilterProcessesUrl(WebSecurityConfig.AUTH_URL);
        log.debug("Set filter process url for custom filter successfully");

        http.exceptionHandling(e -> e.authenticationEntryPoint(customAuthenticationEntryPoint)
            .accessDeniedHandler(customAccessDeniedHandler))
          .authorizeHttpRequests((auth) -> auth
            .requestMatchers(new AntPathRequestMatcher(AUTH_URL + "/**")).permitAll()
            .requestMatchers(HttpMethod.GET, "/api/users").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/users").permitAll()
            .requestMatchers("/api/users/mem").hasAnyAuthority(UserRole.USER.name(), UserRole.MOD.name(), UserRole.ADMIN.name())
            .requestMatchers(PathRequest.toH2Console()).permitAll()
            .anyRequest().authenticated()
          ).sessionManagement(sessionMgmt -> sessionMgmt
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
          ).addFilter(customAuthenticationFilter)
          .httpBasic(withDefaults())
          .csrf(AbstractHttpConfigurer::disable)
          .formLogin(AbstractHttpConfigurer::disable)
          .headers(headers ->
            headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable)
          );

        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        boolean isDevProfile = Arrays.stream(environment.getActiveProfiles()).anyMatch(e -> e.contains("dev"));
        if (isDevProfile) {
            log.debug("Add dev authentication filter");
            http.addFilterBefore(new DevAuthenticationFilter(authenticationManager()), JwtAuthenticationFilter.class);
        }
        return http.build();
    }

    @Bean
    @Profile("!dev")
    public AuthenticationManager authenticationManager() {
        log.debug("Init authentication manager");
        return new ProviderManager(authenticationProvider());
    }

    @Bean("authenticationManager")
    @Profile("dev")
    public AuthenticationManager devAuthenticationManager(DevAuthenticationProvider devAuthenticationProvider) {
        log.debug("Init dev authentication manager");
        return new ProviderManager(devAuthenticationProvider, authenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        authenticationProvider.setUserDetailsService(userDetailsService);
        return authenticationProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        log.debug("Init password encoder bean");
        return new BCryptPasswordEncoder();
    }

}
