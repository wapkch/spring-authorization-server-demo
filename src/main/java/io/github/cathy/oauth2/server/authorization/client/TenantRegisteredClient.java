package io.github.cathy.oauth2.server.authorization.client;

import com.zhongan.multitenancy.context.TenantContext;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

import lombok.Getter;
import lombok.Setter;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.util.SpringAuthorizationServerVersion;
import org.springframework.util.Assert;

@Getter
@Setter
public class TenantRegisteredClient extends RegisteredClient {

    private TenantContext tenantContext;

    private String channel;

    public static Builder withId(String id) {
        Assert.hasText(id, "id cannot be empty");
        return new Builder(id);
    }

    public static class Builder extends RegisteredClient.Builder {

        private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;
        private String id;
        private String clientId;
        private Instant clientIdIssuedAt;
        private String clientSecret;
        private Instant clientSecretExpiresAt;
        private String clientName;
        private final Set<ClientAuthenticationMethod> clientAuthenticationMethods = new HashSet<>();
        private final Set<AuthorizationGrantType> authorizationGrantTypes = new HashSet<>();
        private final Set<String> redirectUris = new HashSet<>();
        private final Set<String> scopes = new HashSet<>();
        private ClientSettings clientSettings;
        private TokenSettings tokenSettings;

        private TenantContext tenantContext;

        private String channel;

        protected Builder(String id) {
            super(id);
        }

        protected Builder(TenantRegisteredClient registeredClient) {
            super(registeredClient);
        }

        public Builder tenantContext(TenantContext tenantContext) {
            this.tenantContext = tenantContext;
            return this;
        }

        public Builder channel(String channel) {
            this.channel = channel;
            return this;
        }

        public Builder id(String id) {
            this.id = id;
            return this;
        }

        /**
         * Sets the client identifier.
         *
         * @param clientId the client identifier
         * @return the {@link Builder}
         */
        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        /**
         * Sets the time at which the client identifier was issued.
         *
         * @param clientIdIssuedAt the time at which the client identifier was issued
         * @return the {@link Builder}
         */
        public Builder clientIdIssuedAt(Instant clientIdIssuedAt) {
            this.clientIdIssuedAt = clientIdIssuedAt;
            return this;
        }

        /**
         * Sets the client secret.
         *
         * @param clientSecret the client secret
         * @return the {@link Builder}
         */
        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        /**
         * Sets the time at which the client secret expires or {@code null} if it does not expire.
         *
         * @param clientSecretExpiresAt the time at which the client secret expires or {@code null} if it does not expire
         * @return the {@link Builder}
         */
        public Builder clientSecretExpiresAt(Instant clientSecretExpiresAt) {
            this.clientSecretExpiresAt = clientSecretExpiresAt;
            return this;
        }

        /**
         * Sets the client name.
         *
         * @param clientName the client name
         * @return the {@link Builder}
         */
        public Builder clientName(String clientName) {
            this.clientName = clientName;
            return this;
        }

        /**
         * Adds an {@link ClientAuthenticationMethod authentication method}
         * the client may use when authenticating with the authorization server.
         *
         * @param clientAuthenticationMethod the authentication method
         * @return the {@link Builder}
         */
        public Builder clientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod) {
            this.clientAuthenticationMethods.add(clientAuthenticationMethod);
            return this;
        }

        /**
         * A {@code Consumer} of the {@link ClientAuthenticationMethod authentication method(s)}
         * allowing the ability to add, replace, or remove.
         *
         * @param clientAuthenticationMethodsConsumer a {@code Consumer} of the authentication method(s)
         * @return the {@link Builder}
         */
        public Builder clientAuthenticationMethods(
            Consumer<Set<ClientAuthenticationMethod>> clientAuthenticationMethodsConsumer) {
            clientAuthenticationMethodsConsumer.accept(this.clientAuthenticationMethods);
            return this;
        }

        /**
         * Adds an {@link AuthorizationGrantType authorization grant type} the client may use.
         *
         * @param authorizationGrantType the authorization grant type
         * @return the {@link Builder}
         */
        public Builder authorizationGrantType(AuthorizationGrantType authorizationGrantType) {
            this.authorizationGrantTypes.add(authorizationGrantType);
            return this;
        }

        /**
         * A {@code Consumer} of the {@link AuthorizationGrantType authorization grant type(s)}
         * allowing the ability to add, replace, or remove.
         *
         * @param authorizationGrantTypesConsumer a {@code Consumer} of the authorization grant type(s)
         * @return the {@link Builder}
         */
        public Builder authorizationGrantTypes(Consumer<Set<AuthorizationGrantType>> authorizationGrantTypesConsumer) {
            authorizationGrantTypesConsumer.accept(this.authorizationGrantTypes);
            return this;
        }

        /**
         * Adds a redirect URI the client may use in a redirect-based flow.
         *
         * @param redirectUri the redirect URI
         * @return the {@link Builder}
         */
        public Builder redirectUri(String redirectUri) {
            this.redirectUris.add(redirectUri);
            return this;
        }

        /**
         * A {@code Consumer} of the redirect URI(s)
         * allowing the ability to add, replace, or remove.
         *
         * @param redirectUrisConsumer a {@link Consumer} of the redirect URI(s)
         * @return the {@link Builder}
         */
        public Builder redirectUris(Consumer<Set<String>> redirectUrisConsumer) {
            redirectUrisConsumer.accept(this.redirectUris);
            return this;
        }

        /**
         * Adds a scope the client may use.
         *
         * @param scope the scope
         * @return the {@link Builder}
         */
        public Builder scope(String scope) {
            this.scopes.add(scope);
            return this;
        }

        /**
         * A {@code Consumer} of the scope(s)
         * allowing the ability to add, replace, or remove.
         *
         * @param scopesConsumer a {@link Consumer} of the scope(s)
         * @return the {@link Builder}
         */
        public Builder scopes(Consumer<Set<String>> scopesConsumer) {
            scopesConsumer.accept(this.scopes);
            return this;
        }

        /**
         * Sets the {@link ClientSettings client configuration settings}.
         *
         * @param clientSettings the client configuration settings
         * @return the {@link Builder}
         */
        public Builder clientSettings(ClientSettings clientSettings) {
            this.clientSettings = clientSettings;
            return this;
        }

        /**
         * Sets the {@link TokenSettings token configuration settings}.
         *
         * @param tokenSettings the token configuration settings
         * @return the {@link Builder}
         */
        public Builder tokenSettings(TokenSettings tokenSettings) {
            this.tokenSettings = tokenSettings;
            return this;
        }

    }

}
