package com.example.springsecurityoauth2example.authentication;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpMethod;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;

import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class OidcClientRegistrationAuthenticationConverter implements AuthenticationConverter {

    private final HttpMessageConverter<OidcClientRegistration> clientRegistrationHttpMessageConverter;


    @Override
    public Authentication convert(HttpServletRequest request) {
        Authentication principal = SecurityContextHolder.getContext().getAuthentication();

        if (HttpMethod.POST.matches(request.getMethod())) {
            try {
                request.setAttribute("redirect_uris", List.of(""));
                OidcClientRegistration clientRegistration = this.clientRegistrationHttpMessageConverter.read(
                        OidcClientRegistration.class, new ServletServerHttpRequest(request)
                );
                log.info("Client: {}", clientRegistration);

                return new OidcClientRegistrationAuthenticationToken(principal, clientRegistration);
            } catch (Exception ex) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, ex.getMessage(), null);
                throw new OAuth2AuthenticationException(error, ex);
            }
        }

        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        if (StringUtils.isNotBlank(clientId) || request.getParameterValues(OAuth2ParameterNames.CLIENT_ID).length != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        return new OidcClientRegistrationAuthenticationToken(principal, clientId);
    }
}
