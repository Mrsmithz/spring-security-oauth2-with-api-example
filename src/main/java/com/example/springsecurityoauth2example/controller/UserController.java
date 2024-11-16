package com.example.springsecurityoauth2example.controller;

import com.example.springsecurityoauth2example.entity.Oauth2RegisteredClient;
import com.example.springsecurityoauth2example.entity.User;
import com.example.springsecurityoauth2example.model.request.CreateUserRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

@RequestMapping("/api/user")
public interface UserController {

    @PostMapping("/create")
    ResponseEntity<User> createUser(@RequestBody CreateUserRequest request);

    @PostMapping("/oauth2")
    ResponseEntity<Oauth2RegisteredClient> createRegisteredClient();
}
