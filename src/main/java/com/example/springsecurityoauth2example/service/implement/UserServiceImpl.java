package com.example.springsecurityoauth2example.service.implement;

import com.example.springsecurityoauth2example.entity.Oauth2RegisteredClient;
import com.example.springsecurityoauth2example.entity.User;
import com.example.springsecurityoauth2example.mapper.UserMapper;
import com.example.springsecurityoauth2example.model.request.CreateUserRequest;
import com.example.springsecurityoauth2example.repository.Oauth2RegisteredClientRepository;
import com.example.springsecurityoauth2example.repository.UserRepository;
import com.example.springsecurityoauth2example.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserMapper userMapper;
    private final UserRepository userRepository;
    private final Oauth2RegisteredClientRepository oauth2RegisteredClientRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public User createUser(CreateUserRequest request) {
        return userRepository.save(userMapper.mapToUser(request));
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public Oauth2RegisteredClient createOauth2RegisteredClient() {
        Oauth2RegisteredClient registeredClient = Oauth2RegisteredClient.builder()
                .clientName("test@test.com")
                .clientId("client")
                .clientSecret(passwordEncoder.encode("secret"))
                .clientIdIssuedAt(Instant.now())
                .clientSecretExpiresAt(Instant.now().plus(365, ChronoUnit.DAYS))
                .scopes("email")
                .build();
        return oauth2RegisteredClientRepository.save(registeredClient);
    }
}
