package io.github.cathy.oauth2.server.authorization.token;

import com.zhongan.multitenancy.context.TenantContext;

import io.github.cathy.oauth2.server.authorization.AttributeGrantedAuthority;
import io.github.cathy.oauth2.server.authorization.TenantUserDetails;
import io.github.cathy.oauth2.server.authorization.constants.Constants;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;

import javax.swing.text.html.Option;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
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
        OAuth2TokenClaimsSet.Builder builder = context.get(OAuth2TokenClaimsSet.Builder.class);
        if (builder == null) return;

        final AuthorizationGrantType grantType = context.getAuthorizationGrantType();

        if (grantType.equals(CLIENT_CREDENTIALS)) {
            RegisteredClient registeredClient = context.getRegisteredClient();
            final TenantContext tenantContext = registeredClient.getClientSettings().getSetting(TenantContext.class.getName());
            builder.claim(Constants.TENANT, tenantContext.getTenant());
            if (!tenantContext.getAttributes().isEmpty()) {
                builder.claim(Constants.TRACE, tenantContext.getAttributes());
            }
            final String channel = registeredClient.getClientSettings().getSetting(Constants.CHANNEL);
            builder.claim(Constants.CHANNEL, channel);
        }

        if (grantType.equals(AUTHORIZATION_CODE)) {
            Authentication principal = context.getPrincipal();
            if (principal.getPrincipal() instanceof TenantUserDetails userDetails) {
                TenantContext tenantContext = userDetails.getTenantContext();
                builder.claim(Constants.TENANT, tenantContext.getTenant());
                if (!tenantContext.getAttributes().isEmpty()) {
                    builder.claim(Constants.TRACE, tenantContext.getAttributes());
                }
                builder.claim(Constants.USER_ID, userDetails.getUserId());
                builder.claim(Constants.USERNAME, userDetails.getUsername());
                builder.claim(Constants.AUTHORITIES, userDetails.getAuthorities());
            }
        }
    }

}
