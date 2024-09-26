package com.irtic.art.security;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    private final static String SUPERADMIN = "SUPERADMIN";

    @Bean
    public AuthenticationManager authManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, JwtRequestFilter jwtRequestFilter) throws Exception {
        http.csrf().disable()
            .authorizeHttpRequests (authorizeRequests ->
                authorizeRequests
                .requestMatchers("/auth/login", "/v3/api-docs/**",
                "/swagger-ui/**",
                "/swagger-ui.html").permitAll()
                .requestMatchers("/usuarios", "/usuarios/**").hasAnyAuthority(SUPERADMIN)
                .requestMatchers("/organizaciones/**").hasAnyAuthority("ADMIN", SUPERADMIN)
                .requestMatchers("/declaraciones/**").hasAnyAuthority("ADMIN", SUPERADMIN)
                .anyRequest().authenticated()
            )
            .httpBasic(withDefaults());

        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }

}
