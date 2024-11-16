package com.example.springsecurityoauth2example.service;

import com.example.springsecurityoauth2example.model.google.GoogleUserProfile;

import java.io.IOException;
import java.security.GeneralSecurityException;

public interface GoogleService {

    GoogleUserProfile verifyGoogleIdToken(String idToken) throws GeneralSecurityException, IOException;
}
