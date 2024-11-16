package com.example.springsecurityoauth2example.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

import java.util.Objects;

public class BaseProvider {

    protected OAuth2ClientAuthenticationToken getAuthenticatedClient(Authentication authentication) {
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            OAuth2ClientAuthenticationToken clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();

            if (Objects.nonNull(clientPrincipal) && clientPrincipal.isAuthenticated()) {
                return clientPrincipal;
            } else {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
            }
        }

        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }

}
