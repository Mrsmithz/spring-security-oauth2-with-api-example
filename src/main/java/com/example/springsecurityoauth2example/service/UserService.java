package com.example.springsecurityoauth2example.service;

import com.example.springsecurityoauth2example.entity.Oauth2RegisteredClient;
import com.example.springsecurityoauth2example.entity.User;
import com.example.springsecurityoauth2example.model.request.CreateUserRequest;

import java.util.Optional;

public interface UserService {

    User createUser(CreateUserRequest request);

    Optional<User> findByEmail(String email);

    Oauth2RegisteredClient createOauth2RegisteredClient();
}
