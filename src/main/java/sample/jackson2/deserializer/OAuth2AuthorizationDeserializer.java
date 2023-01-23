package sample.jackson2.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

import static org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Builder;
import static org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token;
import static org.springframework.security.oauth2.server.authorization.OAuth2Authorization.withRegisteredClient;

public class OAuth2AuthorizationDeserializer extends JsonDeserializer<OAuth2Authorization> {

    private final RegisteredClientRepository registeredClientRepository;

    private static final TypeReference<Set<String>> SET_TYPE_REFERENCE = new TypeReference<>() {
    };

    private static final TypeReference<Map<String, Object>> MAP_TYPE_REFERENCE = new TypeReference<>() {
    };

    private static final TypeReference<AuthorizationGrantType> GRANT_TYPE_TYPE_REFERENCE = new TypeReference<>() {
    };

    public OAuth2AuthorizationDeserializer(RegisteredClientRepository registeredClientRepository) {
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public OAuth2Authorization deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
        ObjectMapper mapper = (ObjectMapper) jp.getCodec();
        JsonNode jsonNode = mapper.readTree(jp);

        Set<String> authorizedScopes = mapper.convertValue(jsonNode.get("authorizedScopes"), SET_TYPE_REFERENCE);
        Map<String, Object> attributes = mapper.convertValue(jsonNode.get("attributes"), MAP_TYPE_REFERENCE);
        Map<String, Object> tokens = mapper.convertValue(jsonNode.get("tokens"), MAP_TYPE_REFERENCE);
        AuthorizationGrantType grantType = mapper.convertValue(jsonNode.get("authorizationGrantType"), GRANT_TYPE_TYPE_REFERENCE);

        String id = readJsonNode(jsonNode, "id").asText();
        String registeredClientId = readJsonNode(jsonNode, "registeredClientId").asText();
        String principalName = readJsonNode(jsonNode, "principalName").asText();

        RegisteredClient registeredClient = registeredClientRepository.findById(registeredClientId);
        Assert.notNull(registeredClient, "Registered client must not be null");

        Builder builder = withRegisteredClient(registeredClient)
            .id(id)
            .principalName(principalName)
            .authorizationGrantType(grantType)
            .authorizedScopes(authorizedScopes)
            .attributes(map -> map.putAll(attributes));

        Optional.ofNullable(tokens.get(OAuth2AuthorizationCode.class.getName())).ifPresent(
            token -> addToken((Token) token, builder));
        Optional.ofNullable(tokens.get(OAuth2AccessToken.class.getName())).ifPresent(
            token -> addToken((Token) token, builder));
        Optional.ofNullable(tokens.get(OAuth2RefreshToken.class.getName())).ifPresent(
            token -> addToken((Token) token, builder));
        Optional.ofNullable(tokens.get(OidcIdToken.class.getName())).ifPresent(
            token -> addToken((Token) token, builder));

        return builder.build();
    }

    public void addToken(OAuth2Authorization.Token<OAuth2Token> token, Builder builder) {
        builder.token(token.getToken(), map -> map.putAll(token.getMetadata()));
    }

    private JsonNode readJsonNode(JsonNode jsonNode, String field) {
        return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
    }

}
