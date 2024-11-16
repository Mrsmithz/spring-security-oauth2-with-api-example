package com.example.springsecurityoauth2example.model.authentication;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AdditionalClaims {

    private Boolean emailVerified;
    private String name;
    private String familyName;
    private String givenName;
    private String picture;
    private String locale;
}
