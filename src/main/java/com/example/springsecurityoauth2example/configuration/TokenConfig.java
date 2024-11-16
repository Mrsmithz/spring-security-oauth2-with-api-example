package com.example.springsecurityoauth2example.configuration;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.UUID;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class TokenConfig {

    private static final Long accessTokenTTL = 24L;
    private static final Long refreshTokenTTL = 365L;
    private final OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer;

    @Value("${jwt.private-key}")
    private final String privateKey;

    @Value("${jwt.public-key}")
    private final String publicKey;

    @Bean
    public TokenSettings tokenSettings() {
        log.info("accessToken TTL: {} hours", accessTokenTTL);
        log.info("refreshToken TTL: {} days", refreshTokenTTL);
        return TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofHours(accessTokenTTL))
                .refreshTokenTimeToLive(Duration.ofDays(refreshTokenTTL))
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                .reuseRefreshTokens(false)
                .idTokenSignatureAlgorithm(SignatureAlgorithm.PS256)
                .build();
    }

    @Bean
    public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
        jwtGenerator.setJwtCustomizer(jwtCustomizer);

        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator, accessTokenGenerator, refreshTokenGenerator
        );
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws GeneralSecurityException {
        JWKSet jwkSet = new JWKSet(generateKey());
        return ((jwkSelector, securityContext) -> jwkSelector.select(jwkSet));
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    private RSAPublicKey publicKey() throws GeneralSecurityException {
        byte[] encoded = Base64.decode(publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
    }

    private PrivateKey privateKey() throws GeneralSecurityException {
        byte[] encoded = Base64.decode(privateKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }

    private RSAKey generateKey() throws GeneralSecurityException {
        return new RSAKey
                .Builder(publicKey())
                .privateKey(privateKey())
                .keyID(UUID.randomUUID().toString())
                .build();
    }
}
