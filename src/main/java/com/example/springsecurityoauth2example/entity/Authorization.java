package com.example.springsecurityoauth2example.entity;

import com.example.springsecurityoauth2example.constant.TokenStatus;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.time.Instant;

@Getter
@Setter
@Builder
@Document(collection = "authorization")
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class Authorization {

    @Id
    private String id;

    @Field("client_id")
    private String clientId;

    @Field("username")
    private String userName;

    @Field("authorization_grant_type")
    private AuthorizationGrantType authorizationGrantType;

    @Field("attributes")
    private String attributes;

    @Field("authorized_scopes")
    private String authorizedScopes;

    @Field("access_token_value")
    private String accessTokenValue;

    @Field("access_token_issued_at")
    private Instant accessTokenIssuedAt;

    @Field("access_token_expired_at")
    private Instant accessTokenExpiredAt;

    @Field("access_token_scopes")
    private String accessTokenScopes;

    @Field("access_token_metadata")
    private String accessTokenMetadata;

    @Field("refresh_token_value")
    private String refreshTokenValue;

    @Field("refresh_token_issued_at")
    private Instant refreshTokenIssuedAt;

    @Field("refresh_token_expired_at")
    private Instant refreshTokenExpiredAt;

    @Field("token_status")
    private TokenStatus tokenStatus;
}
