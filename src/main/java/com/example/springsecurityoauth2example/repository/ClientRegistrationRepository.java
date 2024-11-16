package com.example.springsecurityoauth2example.repository;

import com.example.springsecurityoauth2example.authentication.GoogleAuthenticationToken;
import com.example.springsecurityoauth2example.cache.RedisCacheHelper;
import com.example.springsecurityoauth2example.entity.Oauth2RegisteredClient;
import com.mongodb.DuplicateKeyException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.Objects;
import java.util.Set;

import static com.example.springsecurityoauth2example.constant.CacheConstant.REGISTERED_CLIENT_CACHE_NAME;

@Slf4j
@Component
@RequiredArgsConstructor
public class ClientRegistrationRepository implements RegisteredClientRepository {

    private final TokenSettings tokenSettings;
    private final RedisCacheHelper redisCacheHelper;
    private final Oauth2RegisteredClientRepository oauth2RegisteredClientRepository;

    @Override
    public void save(RegisteredClient registeredClient) {
        try {
            Oauth2RegisteredClient entity = registeredClientToEntity(registeredClient);
            Oauth2RegisteredClient savedEntity = oauth2RegisteredClientRepository.save(entity);
            redisCacheHelper.putRegisteredClientCache(registeredClient);

            log.info("clientId: {} saved successfully", savedEntity.getClientId());

        } catch (DuplicateKeyException ex) {
            log.error("clientId: {} is already exists", registeredClient.getClientId());
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(String.valueOf(HttpStatus.BAD_REQUEST.value())),
                    String.format("clientId (%s) is already exists", registeredClient.getClientId())
            );
        } catch (Exception ex) {
            log.error("save registered client error", ex);
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(String.valueOf(HttpStatus.INTERNAL_SERVER_ERROR.value())),
                    "save registered client error"
            );
        }
    }

    @Override
    public RegisteredClient findById(String id) {
        Oauth2RegisteredClient entity = oauth2RegisteredClientRepository.findById(id)
                .orElse(null);
        if (Objects.nonNull(entity)) {
            log.info("found id {}", id);
            return entityToRegisteredClient(entity);
        }
        log.info("id {} not found", id);
        return null;
    }

    @Override
    @Cacheable(value = REGISTERED_CLIENT_CACHE_NAME, key = "#clientId", cacheManager = "jcache", unless = "#result==null")
    public RegisteredClient findByClientId(String clientId) {
        Oauth2RegisteredClient entity = oauth2RegisteredClientRepository.findByClientId(clientId);
        if (Objects.nonNull(entity)) {
            log.info("found clientId {}", clientId);
            return entityToRegisteredClient(entity);
        }
        log.info("clientId {} not found", clientId);
        return null;
    }

    private Oauth2RegisteredClient registeredClientToEntity(RegisteredClient registeredClient) {
        return Oauth2RegisteredClient.builder()
                .id(registeredClient.getId())
                .clientId(registeredClient.getClientId())
                .clientSecret(registeredClient.getClientSecret())
                .clientName(registeredClient.getClientName())
                .scopes(getScopes(registeredClient))
                .clientIdIssuedAt(registeredClient.getClientIdIssuedAt())
                .clientSecretExpiresAt(registeredClient.getClientSecretExpiresAt())
                .build();

    }

    private RegisteredClient entityToRegisteredClient(Oauth2RegisteredClient entity) {
        Set<String> entityScopes = StringUtils.commaDelimitedListToSet(entity.getScopes());
        return RegisteredClient
                .withId(entity.getId())
                .clientId(entity.getClientId())
                .clientSecret(entity.getClientSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(GoogleAuthenticationToken.AUTHORIZATION_GRANT_TYPE)
                .clientName(entity.getClientName())
                .scopes(scopes -> scopes.addAll(entityScopes))
                .clientIdIssuedAt(entity.getClientIdIssuedAt())
                .clientSecretExpiresAt(entity.getClientSecretExpiresAt())
                .tokenSettings(tokenSettings)
                .redirectUris(uris -> uris.add(""))
                .build();
    }

    private String getScopes(RegisteredClient registeredClient) {
        return String.join(",", registeredClient.getScopes());
    }
}
