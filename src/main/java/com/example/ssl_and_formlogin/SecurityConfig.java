package com.example.ssl_and_formlogin;

import java.nio.file.AccessDeniedException;
import java.util.Collection;
import java.util.function.Supplier;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthoritiesAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    @Order(1)
    SecurityFilterChain x509FilterChain(HttpSecurity http) throws Exception {
        return http
                .securityMatcher("/x509-again/**")
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .x509(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .build();
    }


    @Bean
    @Order(2)
    SecurityFilterChain formLoginFilterChain(HttpSecurity http) throws Exception {
        return http
                // You can comment the security matcher and make this the default chain
                .securityMatcher("/formlogin-again/**")
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .build();
    }

    // OR just this single chain, delete the two chains above
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, UserDetailsService userDetailsService) throws Exception {
        return http
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/public").permitAll();
                    // check type of auth
                    auth.requestMatchers("/x509/**").access((authSupplier, context) -> {
                        return new AuthorizationDecision(authSupplier.get() instanceof CustomX509Authentication);
                    });
                    // or check roles
//                    auth.requestMatchers("/x509/**").hasRole("x509");
                    auth.requestMatchers("/formlogin/**").access((authSupplier, context) -> {
                        var authentication = authSupplier.get();
                        if (authentication == null || !authentication.isAuthenticated() || authentication instanceof AnonymousAuthenticationToken) {
                            return new AuthorizationDecision(false);
                        }
//                        var decision = AuthorityAuthorizationManager.hasRole("x509").check(authSupplier, context);
//                        return new AuthorizationDecision(!decision.isGranted());
                        return new AuthorizationDecision(!(authentication instanceof CustomX509Authentication));
                    });
                    auth.anyRequest().authenticated();
                })
                .x509(x509 -> {
                }) // username: bob
                .authenticationProvider(new CustomX509AuthenticationProvider(userDetailsService))
                .formLogin(Customizer.withDefaults())
                .build();
    }

    static class CustomX509AuthenticationProvider extends PreAuthenticatedAuthenticationProvider {

        public CustomX509AuthenticationProvider(UserDetailsService userDetailsService) {
            UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService = new UserDetailsByNameServiceWrapper<>();
            authenticationUserDetailsService.setUserDetailsService(userDetailsService);
            super.setPreAuthenticatedUserDetailsService(authenticationUserDetailsService);
        }

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            var authResult = super.authenticate(authentication);
            return new CustomX509Authentication(authResult.getPrincipal(), authResult.getCredentials(), authResult.getAuthorities());
        }
    }

    static class CustomX509Authentication extends UsernamePasswordAuthenticationToken {
        public CustomX509Authentication(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
            super(principal, credentials, AuthorityUtils.createAuthorityList("ROLE_x509"));
        }
    }
}
