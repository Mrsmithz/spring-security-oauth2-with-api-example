package com.example.springsecurityoauth2example.controller.implement;

import com.example.springsecurityoauth2example.controller.UserController;
import com.example.springsecurityoauth2example.entity.Oauth2RegisteredClient;
import com.example.springsecurityoauth2example.entity.User;
import com.example.springsecurityoauth2example.model.request.CreateUserRequest;
import com.example.springsecurityoauth2example.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
public class UserControllerImpl implements UserController {

    private final UserService userService;

    @Override
    public ResponseEntity<User> createUser(CreateUserRequest request) {
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(userService.createUser(request));
    }

    @Override
    public ResponseEntity<Oauth2RegisteredClient> createRegisteredClient() {
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(userService.createOauth2RegisteredClient());
    }
}
