package com.example.springsecurityoauth2example.authentication.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.math.NumberUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final HttpMessageConverter<Object> oauth2HttpMessageConverter;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        OAuth2Error error = ((OAuth2AuthenticationException) exception).getError();

        try (ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response)) {
            HttpStatus status = convertErrorCodesToHttpStatus(error.getErrorCode());
            httpResponse.setStatusCode(status);

            log.info("OAuth2Error: {}", error);
            log.error("error", exception);

            oauth2HttpMessageConverter.write(new ResponseEntity<>(status), MediaType.APPLICATION_JSON, httpResponse);
        }
    }

    private HttpStatus convertErrorCodesToHttpStatus(String errorCode) {
        if (!NumberUtils.isCreatable(errorCode)) {
            return switch (errorCode) {
                case OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ErrorCodes.INVALID_GRANT, OAuth2ErrorCodes.INVALID_REQUEST,
                     OAuth2ErrorCodes.INSUFFICIENT_SCOPE, OAuth2ErrorCodes.INVALID_REDIRECT_URI,
                     OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE, OAuth2ErrorCodes.UNSUPPORTED_TOKEN_TYPE ->
                        HttpStatus.BAD_REQUEST;
                case OAuth2ErrorCodes.SERVER_ERROR, OAuth2ErrorCodes.TEMPORARILY_UNAVAILABLE ->
                        HttpStatus.INTERNAL_SERVER_ERROR;
                default -> HttpStatus.UNAUTHORIZED;
            };
        }

        return HttpStatus.INTERNAL_SERVER_ERROR;
    }
}
