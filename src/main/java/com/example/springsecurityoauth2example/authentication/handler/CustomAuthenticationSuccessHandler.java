package com.example.springsecurityoauth2example.authentication.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.io.IOException;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Objects;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final HttpMessageConverter<Object> oauth2HttpMessageConverter;
    private final Converter<OAuth2AccessTokenResponse, Map<String, Object>> oAuth2AccessTokenResponseMapConverter;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2AccessTokenAuthenticationToken accessTokenAuthenticationToken = (OAuth2AccessTokenAuthenticationToken) authentication;

        OAuth2AccessToken accessToken = accessTokenAuthenticationToken.getAccessToken();
        OAuth2RefreshToken refreshToken = accessTokenAuthenticationToken.getRefreshToken();
        Map<String, Object> additionalParameters = accessTokenAuthenticationToken.getAdditionalParameters();

        OAuth2AccessTokenResponse.Builder builder = OAuth2AccessTokenResponse
                .withToken(accessToken.getTokenValue())
                .tokenType(accessToken.getTokenType());

        if (Objects.nonNull(accessToken.getIssuedAt()) && Objects.nonNull(accessToken.getExpiresAt())) {
            builder.expiresIn(ChronoUnit.SECONDS.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()));
        }

        if (Objects.nonNull(refreshToken)) {
            builder.refreshToken(refreshToken.getTokenValue());
        }

        if (!CollectionUtils.isEmpty(additionalParameters)) {
            builder.additionalParameters(additionalParameters);
        }

        OAuth2AccessTokenResponse accessTokenResponse = builder.build();
        Map<String, Object> convertedResponse = oAuth2AccessTokenResponseMapConverter.convert(accessTokenResponse);

        log.info("Authentication successful");

        try (ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response)) {
            Assert.notNull(convertedResponse, "converted response must not be null");
            this.oauth2HttpMessageConverter.write(convertedResponse, MediaType.APPLICATION_JSON, httpResponse);
        }
    }
}
