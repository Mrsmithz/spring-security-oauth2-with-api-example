package com.example.springsecurityoauth2example.service.implement;

import com.example.springsecurityoauth2example.model.google.GoogleUserProfile;
import com.example.springsecurityoauth2example.service.GoogleService;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.Objects;

@Slf4j
@Service
@RequiredArgsConstructor
public class GoogleServiceImpl implements GoogleService {

    private final NetHttpTransport netHttpTransport;
    private final GsonFactory gsonFactory;

    @Value("${google.auth.client-id}")
    private final String clientId;

    public GoogleUserProfile verifyGoogleIdToken(String idToken) throws GeneralSecurityException, IOException {
        try {
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(netHttpTransport, gsonFactory)
                    .setAudience(Collections.singletonList(clientId))
                    .build();

            GoogleIdToken googleIdToken = verifier.verify(idToken);
            if (Objects.isNull(googleIdToken)) {
                throw new IllegalArgumentException("google id token is invalid");
            }

            GoogleIdToken.Payload payload = googleIdToken.getPayload();

            return GoogleUserProfile.builder()
                    .userId(payload.getSubject())
                    .email(payload.getEmail())
                    .emailVerified(payload.getEmailVerified())
                    .name((String) payload.get("name"))
                    .familyName((String) payload.get("family_name"))
                    .givenName((String) payload.get("given_name"))
                    .pictureUrl((String) payload.get("picture"))
                    .locale((String) payload.get("locale"))
                    .build();

        } catch (GeneralSecurityException | IOException ex) {
            log.error(ex.getMessage(), ex);
            throw ex;
        }
    }
}
