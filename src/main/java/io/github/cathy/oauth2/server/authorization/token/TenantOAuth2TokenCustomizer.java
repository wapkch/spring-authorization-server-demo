package io.github.cathy.oauth2.server.authorization.token;

import com.zhongan.multitenancy.context.TenantContext;

import io.github.cathy.oauth2.server.authorization.TenantUserDetails;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS;

@Component
public class TenantOAuth2TokenCustomizer implements OAuth2TokenCustomizer<OAuth2TokenClaimsContext> {

    @Override
    public void customize(OAuth2TokenClaimsContext context) {
        AuthorizationGrantType authorizationGrantType = context.getAuthorizationGrantType();

        if (authorizationGrantType.equals(CLIENT_CREDENTIALS)) {
            RegisteredClient registeredClient = context.getRegisteredClient();
            TenantContext tenantContext = registeredClient.getClientSettings().getSetting("tenantContext");
            String channel = registeredClient.getClientSettings().getSetting("channel");

            OAuth2TokenClaimsSet.Builder builder = context.get(OAuth2TokenClaimsSet.Builder.class);
            builder.claim("tenantContext", tenantContext);
            builder.claim("channel", channel);
        }

        if (authorizationGrantType.equals(AUTHORIZATION_CODE)) {
            Authentication principal = context.getPrincipal();
            if (principal.getPrincipal() instanceof TenantUserDetails) {
                TenantContext tenantContext = ((TenantUserDetails) principal.getPrincipal()).getTenantContext();
                OAuth2TokenClaimsSet.Builder builder = context.get(OAuth2TokenClaimsSet.Builder.class);
                builder.claim("tenantContext", tenantContext);
                builder.claim("user_id", ((TenantUserDetails) principal.getPrincipal()).getUserId());
                builder.claim("user_name", ((TenantUserDetails) principal.getPrincipal()).getUsername());
            }
        }

    }

}
