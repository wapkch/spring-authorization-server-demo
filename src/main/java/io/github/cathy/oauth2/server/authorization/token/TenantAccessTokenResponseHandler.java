package io.github.cathy.oauth2.server.authorization.token;

import com.zhongan.multitenancy.context.DefaultTenantContext;
import com.zhongan.multitenancy.context.TenantContext;

import io.github.cathy.oauth2.server.authorization.constants.Constants;

import java.io.IOException;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

@Component
public class TenantAccessTokenResponseHandler implements AuthenticationSuccessHandler {

    private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter =
        new OAuth2AccessTokenResponseHttpMessageConverter();
    private OAuth2AuthorizationService authorizationService;

    public TenantAccessTokenResponseHandler(OAuth2AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
            (OAuth2AccessTokenAuthenticationToken) authentication;

        OAuth2AccessToken accessToken = accessTokenAuthentication.getAccessToken();
        OAuth2RefreshToken refreshToken = accessTokenAuthentication.getRefreshToken();
        Map<String, Object> additionalParameters = accessTokenAuthentication.getAdditionalParameters();

        // Lookup the authorization using the access token
        final Map<String, Object> additionalParametersToResponse = new HashMap<>();
        OAuth2Authorization authorization = this.authorizationService.findByToken(accessToken.getTokenValue(), OAuth2TokenType.ACCESS_TOKEN);
        if (authorization != null) {
            Map<String, Object> claims = authorization.getAccessToken().getClaims();
            if (!CollectionUtils.isEmpty(claims)) {
                // Add back additionalParameters first
                additionalParametersToResponse.putAll(additionalParameters);

                // Add the claims we need
                Optional.ofNullable(claims.get(Constants.TENANT))
                    .ifPresent(tenant -> additionalParametersToResponse.put(Constants.TENANT, tenant));
                Optional.ofNullable(claims.get(Constants.CHANNEL))
                    .ifPresent(channel -> additionalParametersToResponse.put(Constants.CHANNEL, channel));
                Optional.ofNullable(claims.get(Constants.USER_ID))
                    .ifPresent(userId -> additionalParametersToResponse.put(Constants.USER_ID, userId));
                Optional.ofNullable(claims.get(Constants.USERNAME))
                    .ifPresent(username -> additionalParametersToResponse.put(Constants.USERNAME, username));
            }
        }

        OAuth2AccessTokenResponse.Builder builder =
            OAuth2AccessTokenResponse.withToken(accessToken.getTokenValue())
                .tokenType(accessToken.getTokenType())
                .scopes(accessToken.getScopes());
        if (accessToken.getIssuedAt() != null && accessToken.getExpiresAt() != null) {
            builder.expiresIn(ChronoUnit.SECONDS.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()));
        }
        if (refreshToken != null) {
            builder.refreshToken(refreshToken.getTokenValue());
        }
        if (!CollectionUtils.isEmpty(additionalParametersToResponse)) {
            builder.additionalParameters(additionalParametersToResponse);
        }

        OAuth2AccessTokenResponse accessTokenResponse = builder.build();
        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        this.accessTokenHttpResponseConverter.write(accessTokenResponse, null, httpResponse);
    }

}
