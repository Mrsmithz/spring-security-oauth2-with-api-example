package com.example.springsecurityoauth2example.authentication;

import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Map;
import java.util.Set;

@Getter
public class GoogleAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    public static final AuthorizationGrantType AUTHORIZATION_GRANT_TYPE = new AuthorizationGrantType("gg_authorization_code");
    private final Set<String> scopes;

    protected GoogleAuthenticationToken(Set<String> scopes, Authentication clientPrincipal, Map<String, Object> additionalParameters) {
        super(AUTHORIZATION_GRANT_TYPE, clientPrincipal, additionalParameters);
        this.scopes = Set.copyOf(scopes);
    }

    @Override
    public Object getCredentials() {
        return this.getAdditionalParameters().get(OAuth2ParameterNames.CODE);
    }

    @Override
    public boolean equals(Object obj) {
        return super.equals(obj);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
