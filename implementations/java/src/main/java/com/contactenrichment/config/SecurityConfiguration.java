package com.contactenrichment.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Spring Security configuration for TOS-compliant contact enrichment platform.
 *
 * Security architecture:
 * - Stateless authentication via JWT
 * - mTLS for service-to-service communication
 * - MAC enforcement via custom security filters
 * - CSRF protection disabled (stateless API)
 * - CORS configured for trusted origins only
 *
 * Defense-in-depth layers:
 * 1. TLS 1.3 with mutual authentication (transport)
 * 2. JWT signature verification (authentication)
 * 3. SecurityContext extraction and validation (authorization context)
 * 4. SecurityKernel MAC enforcement (authorization decision)
 * 5. PostgreSQL RLS (data access control)
 * 6. Field-level encryption (data protection)
 * 7. Audit logging (accountability)
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfiguration {

    // TODO: Inject JWT authentication filter
    // private final JwtAuthenticationFilter jwtAuthFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF for stateless API
            .csrf(csrf -> csrf.disable())

            // Configure session management (stateless)
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            // Configure authorization rules
            .authorizeHttpRequests(auth -> auth
                // Public endpoints (health checks, metrics)
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()

                // API endpoints require authentication
                .requestMatchers("/api/**").authenticated()

                // Admin endpoints require ADMIN role
                .requestMatchers("/api/admin/**").hasRole("ADMIN")

                // All other requests denied by default
                .anyRequest().denyAll()
            )

            // Add custom JWT authentication filter
            // .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)

            // Configure security headers
            .headers(headers -> headers
                .contentSecurityPolicy(csp ->
                    csp.policyDirectives("default-src 'self'; frame-ancestors 'none'")
                )
                .frameOptions(frame -> frame.deny())
                // X-XSS-Protection is obsolete; rely on CSP
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000) // 1 year
                )
            );

        return http.build();
    }
}
