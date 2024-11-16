package com.example.springsecurityoauth2example.authentication;

import com.example.springsecurityoauth2example.model.authentication.AdditionalClaims;
import com.example.springsecurityoauth2example.model.authentication.UserDetail;
import com.example.springsecurityoauth2example.service.GoogleService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.security.Principal;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class GoogleAuthenticationProvider extends BaseProvider implements AuthenticationProvider {

    private final OAuth2AuthorizationService oAuth2AuthorizationService;
    private final GoogleService googleService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        GoogleAuthenticationToken googleAuthenticationToken = (GoogleAuthenticationToken) authentication;
        OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClient(authentication);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        if (!clientSupportedGrantType(registeredClient)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        Map<String, Object> additionalParameters = googleAuthenticationToken.getAdditionalParameters();
        String googleIdToken = String.valueOf(additionalParameters.get(OAuth2ParameterNames.CODE));

//        GoogleUserProfile googleUserProfile;
//        try {
//            googleUserProfile = googleService.verifyGoogleIdToken(googleIdToken);
//        } catch (GeneralSecurityException | IOException ex) {
//            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR), ex);
//        }

        Assert.notNull(registeredClient, "registered client not found");
        Set<String> authorizedScopes = registeredClient.getScopes();
        Set<String> requestedScopes = googleAuthenticationToken.getScopes();
        if (!CollectionUtils.isEmpty(requestedScopes)) {
            Set<String> unauthorizedScopes = requestedScopes
                    .parallelStream()
                    .filter(requestedScope -> !authorizedScopes.contains(requestedScope))
                    .collect(Collectors.toSet());
            if (!CollectionUtils.isEmpty(unauthorizedScopes)) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
            }
        }

        AdditionalClaims additionalClaims = AdditionalClaims.builder()
//                .emailVerified(googleUserProfile.isEmailVerified())
//                .name(googleUserProfile.getName())
//                .familyName(googleUserProfile.getFamilyName())
//                .givenName(googleUserProfile.getGivenName())
//                .picture(googleUserProfile.getPictureUrl())
//                .locale(googleUserProfile.getLocale())
                .build();

        UserDetail userDetail = UserDetail.builder()
                .email("test@test.com")
                .enabled(true)
//                .additionalClaims(additionalClaims)
                .build();

        Authentication usernamePasswordAuthentication = new UsernamePasswordAuthenticationToken(userDetail, null);

        DefaultOAuth2TokenContext.Builder tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(usernamePasswordAuthentication)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizationGrantType(GoogleAuthenticationToken.AUTHORIZATION_GRANT_TYPE)
                .authorizedScopes(authorizedScopes)
                .authorizationGrant(googleAuthenticationToken);

        OAuth2TokenContext accessTokenContext = tokenContext.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        OAuth2Token generatedOAuth2Token = tokenGenerator.generate(accessTokenContext);
        if (Objects.isNull(generatedOAuth2Token)) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "access token generate failed", null);
            throw new OAuth2AuthenticationException(error);
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                generatedOAuth2Token.getTokenValue(),
                generatedOAuth2Token.getIssuedAt(),
                generatedOAuth2Token.getExpiresAt(),
                accessTokenContext.getAuthorizedScopes()
        );

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization
                .withRegisteredClient(registeredClient)
                .principalName(userDetail.getUsername())
                .authorizationGrantType(GoogleAuthenticationToken.AUTHORIZATION_GRANT_TYPE)
                .authorizedScopes(authorizedScopes)
                .attribute(Principal.class.getName(), usernamePasswordAuthentication);
        if (generatedOAuth2Token instanceof ClaimAccessor claimAccessor) {
            authorizationBuilder.token(accessToken,
                    metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claimAccessor.getClaims()));
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            OAuth2TokenContext refreshTokenContext = tokenContext.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
            OAuth2Token generatedRefreshToken = tokenGenerator.generate(refreshTokenContext);
            if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "refresh token generate failed", null);
                throw new OAuth2AuthenticationException(error);
            }

            refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
        }

        OAuth2Authorization authorization = authorizationBuilder
                .refreshToken(refreshToken)
                .build();

        oAuth2AuthorizationService.save(authorization);

        return new OAuth2AccessTokenAuthenticationToken(
                registeredClient,
                clientPrincipal,
                accessToken,
                refreshToken,
                additionalParameters);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return GoogleAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private boolean clientSupportedGrantType(RegisteredClient registeredClient) {
        return Objects.nonNull(registeredClient) && registeredClient.getAuthorizationGrantTypes().contains(GoogleAuthenticationToken.AUTHORIZATION_GRANT_TYPE);
    }
}
