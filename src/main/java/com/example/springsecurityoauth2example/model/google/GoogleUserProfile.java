package com.example.springsecurityoauth2example.model.google;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GoogleUserProfile {

    private String userId;
    private String email;
    private boolean emailVerified;
    private String pictureUrl;
    private String locale;
    private String name;
    private String familyName;
    private String givenName;
}
