package com.example.springsecurityoauth2example.service.implement;

import com.example.springsecurityoauth2example.constant.TokenStatus;
import com.example.springsecurityoauth2example.entity.Authorization;
import com.example.springsecurityoauth2example.repository.AuthorizationRepository;
import com.example.springsecurityoauth2example.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bson.Document;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final AuthorizationRepository authorizationRepository;

    @Override
    public void revokeToken(String accessToken) {
        Authorization authorization = authorizationRepository.findByAccessTokenValueAndTokenStatus(accessToken, TokenStatus.ACTIVE);
        if (Objects.isNull(authorization)) {
            throw new IllegalArgumentException(String.format("access token %s not found", accessToken));
        } else {
            authorization.setTokenStatus(TokenStatus.INACTIVE);
            authorization.setAccessTokenMetadata(updateMetaData(authorization.getAccessTokenMetadata()));
            authorizationRepository.save(authorization);
            log.info("revoke token {} successfully", accessToken);
        }
    }

    private String updateMetaData(String metaDataString) {
        Document bsonDocument = Document.parse(metaDataString);
        bsonDocument.put("metadata.token.invalidated", true);
        return bsonDocument.toJson();
    }
}
