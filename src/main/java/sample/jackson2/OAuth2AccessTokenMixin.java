package sample.jackson2;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

import java.time.Instant;
import java.util.Set;

import org.springframework.security.oauth2.core.OAuth2AccessToken;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE,
    isGetterVisibility = JsonAutoDetect.Visibility.NONE)
abstract class OAuth2AccessTokenMixin {

    @JsonCreator
    OAuth2AccessTokenMixin(@JsonProperty("tokenType") OAuth2AccessToken.TokenType tokenType,
                           @JsonProperty("tokenValue") String tokenValue,
                           @JsonProperty("issuedAt") Instant issuedAt,
                           @JsonProperty("expiresAt") Instant expiresAt,
                           @JsonProperty("scopes") Set<String> scopes) {
    }

}
