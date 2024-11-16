package com.example.springsecurityoauth2example.authentication;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.*;
import java.util.stream.Collectors;


@Slf4j
@Component
@RequiredArgsConstructor
public class GoogleAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {

        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        log.info("grantType: {}", grantType);
        if (!GoogleAuthenticationToken.AUTHORIZATION_GRANT_TYPE.getValue().equals(grantType)) {
            return null;
        }

        MultiValueMap<String, String> parameters = getParameters(request);

        String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
        if (!isValidScope(scope, parameters)) {
            parameterErrorHandler(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.SCOPE);
        }

        Set<String> requestedScopes = Optional.ofNullable(StringUtils.split(scope, " "))
                .map(Arrays::asList)
                .map(HashSet::new)
                .orElse(null);

        String code = parameters.getFirst(OAuth2ParameterNames.CODE);
        if (StringUtils.isBlank(code)) {
            parameterErrorHandler(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CODE);
        }

        String redirectUri = parameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
        if (StringUtils.isBlank(redirectUri)) {
            parameterErrorHandler(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI);
        }

        Map<String, Object> additionalParameters = parameters
                .entrySet()
                .stream()
                .filter(entry -> !entry.getKey().equals(OAuth2ParameterNames.GRANT_TYPE) && !entry.getKey().equals(OAuth2ParameterNames.SCOPE))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        return new GoogleAuthenticationToken(
                requestedScopes,
                clientPrincipal,
                additionalParameters
        );
    }

    private MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        Map<String, List<String>> multiValueMap = request
                .getParameterMap()
                .entrySet()
                .stream()
                .map(entry -> new AbstractMap.SimpleEntry<>(entry.getKey(), Arrays.stream(entry.getValue()).toList()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        return new LinkedMultiValueMap<>(multiValueMap);
    }

    private boolean isValidScope(String scope, MultiValueMap<String, String> parameters) {
        return StringUtils.isNotBlank(scope) && parameters.get(OAuth2ParameterNames.SCOPE).size() == 1;
    }

    private void parameterErrorHandler(String errorCode, String parameterName) {
        OAuth2Error error = new OAuth2Error(errorCode, String.format("Parameter: %s", parameterName), null);
        throw new OAuth2AuthenticationException(error);
    }
}
