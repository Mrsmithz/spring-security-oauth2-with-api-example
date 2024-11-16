package com.example.springsecurityoauth2example.configuration;

import com.example.springsecurityoauth2example.authentication.AuthenticationRevocationProvider;
import com.example.springsecurityoauth2example.authentication.DefaultUserDetailsService;
import com.example.springsecurityoauth2example.authentication.GoogleAuthenticationConverter;
import com.example.springsecurityoauth2example.authentication.GoogleAuthenticationProvider;
import com.example.springsecurityoauth2example.authentication.handler.CustomAuthenticationFailureHandler;
import com.example.springsecurityoauth2example.authentication.handler.CustomAuthenticationSuccessHandler;
import com.example.springsecurityoauth2example.authentication.handler.CustomRevocationFailureHandler;
import com.example.springsecurityoauth2example.authentication.handler.CustomRevocationSuccessHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private final GoogleAuthenticationProvider googleAuthenticationProvider;

    private final GoogleAuthenticationConverter googleAuthenticationConverter;

    private final AuthenticationRevocationProvider authenticationRevocationProvider;

    private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;

    private final CustomAuthenticationFailureHandler customAuthenticationFailureHandler;

    private final CustomRevocationSuccessHandler customRevocationSuccessHandler;

    private final CustomRevocationFailureHandler customRevocationFailureHandler;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

        authorizationServerConfigurer
                .tokenEndpoint(tokenEndpoint ->
                        tokenEndpoint
                                .accessTokenRequestConverter(googleAuthenticationConverter)
                                .authenticationProvider(googleAuthenticationProvider)
                                .accessTokenResponseHandler(customAuthenticationSuccessHandler)
                                .errorResponseHandler(customAuthenticationFailureHandler)
                )
                .tokenRevocationEndpoint(tokenEndpoint ->
                        tokenEndpoint
                                .authenticationProvider(authenticationRevocationProvider)
                                .revocationResponseHandler(customRevocationSuccessHandler)
                                .errorResponseHandler(customRevocationFailureHandler)
                )
                .clientAuthentication(clientAuthentication -> clientAuthentication.errorResponseHandler(customAuthenticationFailureHandler));

        RequestMatcher requestMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        return http
                .securityMatchers(requestMatcherConfigurer -> requestMatcherConfigurer
                        .requestMatchers(requestMatcher)
                        .requestMatchers("/api/**")
                )
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers("/api/user/**")
                        .permitAll()
                        .anyRequest()
                        .authenticated()
                )
                .csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))
                .csrf(csrf -> csrf.ignoringRequestMatchers(requestMatcher))
                .with(authorizationServerConfigurer, Customizer.withDefaults())
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    @ConditionalOnMissingBean(UserDetailsService.class)
    public UserDetailsService userDetailsService() {
        return new DefaultUserDetailsService();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(@Value("${provider-setting}") String providerSetting) {
        log.info("provider setting: {}", providerSetting);
        return AuthorizationServerSettings.builder()
                .issuer(providerSetting)
                .tokenEndpoint("/oauth2/token")
                .tokenRevocationEndpoint("/oauth2/logout")
                .tokenIntrospectionEndpoint("/oauth2/introspect")
                .build();
    }
}
