package com.example.springsecurityoauth2example.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.core.endpoint.DefaultOAuth2AccessTokenResponseMapConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.http.converter.OidcClientRegistrationHttpMessageConverter;

import java.util.Map;

@Configuration
public class ConverterConfig {

    @Bean
    public HttpMessageConverter<Object> oauth2HttpMessageConverter() {
        return new MappingJackson2HttpMessageConverter();
    }

    @Bean
    public Converter<OAuth2AccessTokenResponse, Map<String, Object>> oAuth2AccessTokenResponseMapConverter() {
        return new DefaultOAuth2AccessTokenResponseMapConverter();
    }

    @Bean
    public HttpMessageConverter<OidcClientRegistration> clientRegistrationHttpMessageConverter() {
        return new OidcClientRegistrationHttpMessageConverter();
    }

    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }
}
