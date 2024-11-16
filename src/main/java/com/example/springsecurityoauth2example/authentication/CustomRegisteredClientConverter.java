package com.example.springsecurityoauth2example.authentication;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;

import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.Set;

public class CustomRegisteredClientConverter implements Converter<OidcClientRegistration, RegisteredClient> {

    @Override
    public RegisteredClient convert(OidcClientRegistration clientRegistration) {
        Instant clientIdIssuedAt = clientRegistration.getClientIdIssuedAt();
        if (Objects.isNull(clientIdIssuedAt)) {
            clientIdIssuedAt = Instant.now().atOffset(ZoneOffset.UTC).toInstant();
        }

        return RegisteredClient
                .withId(clientRegistration.getClientId())
                .redirectUris(uri -> uri.add(""))
                .clientName(clientRegistration.getClientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantTypes(set -> set.addAll(
                        Set.of(AuthorizationGrantType.CLIENT_CREDENTIALS, AuthorizationGrantType.REFRESH_TOKEN)
                ))
                .clientId(clientRegistration.getClientId())
                .clientIdIssuedAt(clientIdIssuedAt)
                .clientSecret(clientRegistration.getClientSecret())
                .clientSecretExpiresAt(clientRegistration.getClientSecretExpiresAt())
                .scopes(scopes -> scopes.addAll(clientRegistration.getScopes()))
                .build();
    }
}
