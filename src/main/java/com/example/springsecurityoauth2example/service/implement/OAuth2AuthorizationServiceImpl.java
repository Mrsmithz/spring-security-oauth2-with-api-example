package com.example.springsecurityoauth2example.service.implement;

import com.example.springsecurityoauth2example.constant.TokenStatus;
import com.example.springsecurityoauth2example.entity.Authorization;
import com.example.springsecurityoauth2example.repository.AuthorizationRepository;
import com.example.springsecurityoauth2example.repository.ClientRegistrationRepository;
import com.example.springsecurityoauth2example.service.BaseOAuth2Service;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@Primary
public class OAuth2AuthorizationServiceImpl extends BaseOAuth2Service implements OAuth2AuthorizationService {

    private final AuthorizationRepository authorizationRepository;
    private final ClientRegistrationRepository clientRegistrationRepository;

    @Autowired
    public OAuth2AuthorizationServiceImpl(
            AuthorizationRepository authorizationRepository,
            ClientRegistrationRepository clientRegistrationRepository) {
        super();
        this.authorizationRepository = authorizationRepository;
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization can't be null");

        authorizationRepository.save(oauth2ToEntity(authorization));
        log.info("saved {}", authorization.getId());
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization can't be null");

        authorizationRepository.deleteById(authorization.getId());
        log.info("removed {}", authorization.getId());
    }

    @Override
    public OAuth2Authorization findById(String id) {
        Assert.hasText(id, "id can't be empty");

        Authorization authorization = authorizationRepository.findById(id)
                .orElse(null);
        Assert.notNull(authorization, "id not found");

        return entityToOAuth2Authorization(authorization);
    }

    @Override
    public OAuth2Authorization findByToken(String token, @Nullable OAuth2TokenType tokenType) {
        Assert.hasText(token, "token can't be empty");

        if (Objects.isNull(tokenType)) {
            return entityToOAuth2Authorization(authorizationRepository.findByAccessTokenValueOrRefreshTokenValue(token, token));
        } else if (OAuth2ParameterNames.ACCESS_TOKEN.equals(tokenType.getValue())) {
            return entityToOAuth2Authorization(authorizationRepository.findByAccessTokenValue(token));
        } else if (OAuth2ParameterNames.REFRESH_TOKEN.equals(tokenType.getValue())) {
            Authorization authorization = authorizationRepository.findByRefreshTokenValue(token);
            if (TokenStatus.INACTIVE.equals(authorization.getTokenStatus())) {
                throw new OAuth2AuthenticationException(String.valueOf(HttpStatus.UNAUTHORIZED.value()));
            } else {
                return entityToOAuth2Authorization(authorization);
            }
        }

        return null;
    }

    private OAuth2Authorization entityToOAuth2Authorization(Authorization entity) {
        RegisteredClient registeredClient = clientRegistrationRepository.findById(entity.getClientId());
        if (Objects.isNull(registeredClient)) {
            throw new DataRetrievalFailureException(String.format("clientId %s is not found", entity.getClientId()));
        }

        return OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(entity.getId())
                .principalName(entity.getUserName())
                .authorizationGrantType(entity.getAuthorizationGrantType())
                .attributes(attributes -> attributes.putAll(parseMap(entity.getAttributes())))
                .authorizedScopes(getAuthorizedScopes(entity.getAuthorizedScopes()))
                .token(getOAuth2AccessToken(entity), metadata -> metadata.putAll(parseMap(entity.getAccessTokenMetadata())))
                .token(getOAuth2RefreshToken(entity))
                .build();
    }

    private Authorization oauth2ToEntity(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2AccessToken> token = getOAuth2Token(authorization);
        OAuth2AccessToken accessToken = getOAuth2AccessToken(authorization);
        OAuth2RefreshToken refreshToken = getOAuth2RefreshToken(authorization);

        return Authorization.builder()
                .id(authorization.getId())
                .clientId(authorization.getRegisteredClientId())
                .userName(authorization.getPrincipalName())
                .authorizationGrantType(authorization.getAuthorizationGrantType())
                .attributes(writeMap(authorization.getAttributes()))
                .authorizedScopes(getScopes(authorization.getAuthorizedScopes()))
                .accessTokenValue(accessToken.getTokenValue())
                .accessTokenIssuedAt(accessToken.getIssuedAt())
                .accessTokenExpiredAt(accessToken.getExpiresAt())
                .accessTokenScopes(getScopes(accessToken.getScopes()))
                .accessTokenMetadata(writeMap(token.getMetadata()))
                .refreshTokenValue(refreshToken.getTokenValue())
                .refreshTokenIssuedAt(refreshToken.getIssuedAt())
                .refreshTokenExpiredAt(refreshToken.getExpiresAt())
                .tokenStatus(TokenStatus.ACTIVE)
                .build();
    }

    private OAuth2Authorization.Token<OAuth2AccessToken> getOAuth2Token(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getToken(OAuth2AccessToken.class);
        if (Objects.isNull(accessToken)) {
            throw new IllegalArgumentException("Access token not found");
        }

        return accessToken;
    }

    private OAuth2RefreshToken getOAuth2RefreshToken(Authorization entity) {
        return new OAuth2RefreshToken(
                entity.getAccessTokenValue(),
                entity.getRefreshTokenIssuedAt(),
                entity.getRefreshTokenExpiredAt()
        );
    }

    private OAuth2AccessToken getOAuth2AccessToken(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getToken(OAuth2AccessToken.class);
        if (Objects.isNull(accessToken)) {
            throw new IllegalArgumentException("Access token not found");
        }

        return accessToken.getToken();
    }

    private OAuth2RefreshToken getOAuth2RefreshToken(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getToken(OAuth2RefreshToken.class);
        if (Objects.isNull(refreshToken)) {
            throw new IllegalArgumentException("Refresh token not found");
        }

        return refreshToken.getToken();
    }

    private OAuth2AccessToken getOAuth2AccessToken(Authorization entity) {
        Set<String> accessTokenScopes = Arrays.stream(entity.getAccessTokenScopes().split(",")).collect(Collectors.toSet());
        return new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                entity.getAccessTokenValue(),
                entity.getAccessTokenIssuedAt(),
                entity.getAccessTokenExpiredAt(),
                accessTokenScopes
        );
    }

    private Set<String> getAuthorizedScopes(String authorizedScopes) {
        if (Strings.isBlank(authorizedScopes)) {
            return Collections.emptySet();
        }

        return Arrays.stream(authorizedScopes.split(",")).collect(Collectors.toSet());
    }

    private String getScopes(Set<String> scopes) {
        if (CollectionUtils.isEmpty(scopes)) {
            return null;
        }

        return StringUtils.join(scopes, ",");
    }

}
