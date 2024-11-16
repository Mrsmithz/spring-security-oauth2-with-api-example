package com.example.springsecurityoauth2example.repository;

import com.example.springsecurityoauth2example.constant.TokenStatus;
import com.example.springsecurityoauth2example.entity.Authorization;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthorizationRepository extends MongoRepository<Authorization, String> {

    Authorization findByAccessTokenValue(String accessToken);

    Authorization findByRefreshTokenValue(String refreshToken);

    Authorization findByAccessTokenValueAndTokenStatus(String accessToken, TokenStatus status);

    Authorization findByAccessTokenValueOrRefreshTokenValue(String accessToken, String refreshToken);
}
