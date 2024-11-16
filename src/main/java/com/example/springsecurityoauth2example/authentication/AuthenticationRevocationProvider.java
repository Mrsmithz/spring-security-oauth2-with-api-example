package com.example.springsecurityoauth2example.authentication;

import com.example.springsecurityoauth2example.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.Objects;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthenticationRevocationProvider extends BaseProvider implements AuthenticationProvider {

    private final OAuth2AuthorizationService authorizationService;

    private final AuthenticationService authenticationService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2TokenRevocationAuthenticationToken revocationAuthenticationToken =
                (OAuth2TokenRevocationAuthenticationToken) authentication;
        OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClient(authentication);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        OAuth2Authorization authorization = authorizationService.findByToken(revocationAuthenticationToken.getToken(), null);
        if (Objects.isNull(authorization)) {
            log.info("token not found");
            return revocationAuthenticationToken;
        }

        if (Objects.nonNull(registeredClient) && !registeredClient.getId().equals(authorization.getRegisteredClientId())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }

        OAuth2Authorization.Token<OAuth2Token> token = authorization.getToken(revocationAuthenticationToken.getToken());

        Assert.notNull(token, "token is null");
        OAuth2Authorization invalidatedToken = invalidateToken(authorization, token.getToken());
        authorizationService.save(invalidatedToken);
        authenticationService.revokeToken(revocationAuthenticationToken.getToken());

        return new OAuth2TokenRevocationAuthenticationToken(token.getToken(), clientPrincipal);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2TokenRevocationAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private <T extends OAuth2Token> OAuth2Authorization invalidateToken(OAuth2Authorization authorization, T token) {
        OAuth2Authorization.Builder builder = OAuth2Authorization.from(authorization)
                .token(token, metadata -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));

        if (OAuth2RefreshToken.class.isAssignableFrom(token.getClass())) {
            builder.token(
                    authorization.getAccessToken().getToken(),
                    metadata -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true)
            );

            OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCodeToken = authorization.getToken(OAuth2AuthorizationCode.class);
            if (Objects.nonNull(authorizationCodeToken) && !authorizationCodeToken.isInvalidated()) {
                builder.token(
                        authorizationCodeToken.getToken(),
                        metadata -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true)
                );
            }
        }

        return builder.build();
    }

}
