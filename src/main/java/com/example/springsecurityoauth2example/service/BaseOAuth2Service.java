package com.example.springsecurityoauth2example.service;

import com.example.springsecurityoauth2example.model.authentication.UserDetail;
import com.example.springsecurityoauth2example.model.authentication.UserDetailMixin;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;

import java.util.List;
import java.util.Map;

public abstract class BaseOAuth2Service {

    private final ObjectMapper objectMapper = new ObjectMapper();

    protected BaseOAuth2Service() {
        ClassLoader classLoader = OAuth2AuthorizationService.class.getClassLoader();
        List<Module> moduleList = SecurityJackson2Modules.getModules(classLoader);
        this.objectMapper.registerModules(moduleList);
        this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        this.objectMapper.addMixIn(UserDetail.class, UserDetailMixin.class);
    }

    protected Map<String, Object> parseMap(String data) {
        try {
            return this.objectMapper.readValue(data, new TypeReference<>() {
            });
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

    protected String writeMap(Map<String, Object> data) {
        try {
            return this.objectMapper.writeValueAsString(data);
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }
}
