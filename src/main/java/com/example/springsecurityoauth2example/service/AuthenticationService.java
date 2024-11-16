package com.example.springsecurityoauth2example.service;

public interface AuthenticationService {

    void revokeToken(String accessToken);
}
