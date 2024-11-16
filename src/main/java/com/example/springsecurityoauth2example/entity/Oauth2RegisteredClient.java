package com.example.springsecurityoauth2example.entity;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Builder;
import lombok.Getter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;
import org.springframework.data.mongodb.core.mapping.FieldType;
import org.springframework.data.mongodb.core.mapping.MongoId;

import java.time.Instant;

@Getter
@Builder
@Document(collection = "oauth2_registered_client")
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class Oauth2RegisteredClient {

    @Id
    @MongoId(FieldType.OBJECT_ID)
    private String id;

    @Indexed(unique = true)
    @Field("client_id")
    private String clientId;

    @Field("client_id_issued_at")
    private Instant clientIdIssuedAt;

    @Field("client_secret")
    private String clientSecret;

    @Field("client_secret_expires_at")
    private Instant clientSecretExpiresAt;

    @Field("client_name")
    private String clientName;

    @Field("scopes")
    private String scopes;
}
