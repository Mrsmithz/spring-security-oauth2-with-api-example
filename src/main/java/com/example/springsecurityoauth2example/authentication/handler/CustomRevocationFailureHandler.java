package com.example.springsecurityoauth2example.authentication.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomRevocationFailureHandler implements AuthenticationFailureHandler {

    private final HttpMessageConverter<Object> oauth2HttpMessageConverter;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        OAuth2Error error = ((OAuth2AuthenticationException) exception).getError();

        try (ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response)) {
            httpResponse.setStatusCode(HttpStatus.UNAUTHORIZED);

            log.info("OAuth2Error: {}", error);

            oauth2HttpMessageConverter.write(new ResponseEntity<>(HttpStatus.UNAUTHORIZED), MediaType.APPLICATION_JSON, httpResponse);
        }
    }
}
