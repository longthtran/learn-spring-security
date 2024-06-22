package org.example.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.entity.UserRole;
import org.example.service.security.CustomAuthenticationFilter;
import org.example.service.security.JwtTokenProvider;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.springframework.security.config.Customizer.withDefaults;

// https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@AllArgsConstructor
@Slf4j
public class WebSecurityConfig {

    private final ObjectMapper objectMapper;

    public static final String AUTH_URL = "/api/auth";

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider) throws Exception {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManager, jwtTokenProvider, objectMapper);
        customAuthenticationFilter.setFilterProcessesUrl(WebSecurityConfig.AUTH_URL);
        log.debug("Set filter process url for custom filter successfully");

        http
          .authorizeHttpRequests((auth) -> auth
            .requestMatchers(new AntPathRequestMatcher(AUTH_URL + "/**")).permitAll()
            .requestMatchers(HttpMethod.GET, "/api/users").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/users").permitAll()
            .requestMatchers("/api/users/mem").hasAuthority(UserRole.USER.name())
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
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        log.debug("Init password encoder bean");
        return new BCryptPasswordEncoder();
    }

}
