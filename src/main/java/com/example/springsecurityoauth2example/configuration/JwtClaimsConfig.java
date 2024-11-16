package com.example.springsecurityoauth2example.configuration;

import com.example.springsecurityoauth2example.model.authentication.AdditionalClaims;
import com.example.springsecurityoauth2example.model.authentication.UserDetail;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ObjectUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class JwtClaimsConfig {

    private final ObjectMapper objectMapper;

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()) && context.getPrincipal() instanceof UsernamePasswordAuthenticationToken) {
                Optional.ofNullable(context.getPrincipal().getPrincipal()).ifPresent(
                        principal -> {
                            JwtClaimsSet.Builder builder = context.getClaims();
                            AdditionalClaims additionalClaims = ((UserDetail) principal).getAdditionalClaims();
                            Map<String, Object> claimsMap = getClaimsMap(additionalClaims);
                            claimsMap.forEach(builder::claim);
                        }
                );
            }
        };
    }

    private Map<String, Object> getClaimsMap(AdditionalClaims additionalClaims) {
        if (ObjectUtils.isNotEmpty(additionalClaims)) {
            try {
                Map<String, Object> claimsMap = objectMapper.convertValue(additionalClaims, new TypeReference<>() {
                });
                return claimsMap
                        .entrySet()
                        .stream()
                        .filter(entry -> ObjectUtils.isNotEmpty(entry.getValue()))
                        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            } catch (Exception ex) {
                log.error("error while convert jwt claims: {}", ex.getMessage(), ex);
            }
        }

        return new HashMap<>();
    }
}
