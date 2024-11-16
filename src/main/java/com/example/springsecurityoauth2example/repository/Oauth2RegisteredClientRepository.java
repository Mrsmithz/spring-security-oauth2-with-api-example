package com.example.springsecurityoauth2example.repository;

import com.example.springsecurityoauth2example.entity.Oauth2RegisteredClient;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface Oauth2RegisteredClientRepository extends MongoRepository<Oauth2RegisteredClient, String> {

    Oauth2RegisteredClient findByClientId(String clientId);
}
