package sample.redis;

import sample.jackson2.OAuth2Module;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.http.converter.json.SpringHandlerInstantiator;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.util.Assert;

public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private static final String ID_TO_AUTHORIZATION = "id_to_authorization:";

    private static final String STATE_TO_AUTHORIZATION = "state_to_authorization:";

    private static final String CODE_TO_AUTHORIZATION = "code_to_authorization:";

    private static final String ACCESS_TO_AUTHORIZATION = "access_to_authorization:";

    private static final String REFRESH_TO_AUTHORIZATION = "refresh_to_authorization:";

    private static final String ID_TO_CORRELATIONS = "id_to_correlations:";

    private static final MessageDigest digest;

    private final RedisOperations<String, String> redisOperations;

    private final RegisteredClientRepository clientRepository;

    private final RedisScript<String> saveScript;

    private ObjectMapper objectMapper = new ObjectMapper();

    private String prefix = "";

    static {
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public RedisOAuth2AuthorizationService(RedisOperations<String, String> redisOperations,
                                           RegisteredClientRepository clientRepository,
                                           RedisScript<String> saveScript, AutowireCapableBeanFactory beanFactory) {
        Assert.notNull(redisOperations, "redisOperations mut not be null");
        this.redisOperations = redisOperations;
        this.clientRepository = clientRepository;
        this.saveScript = saveScript;
        ClassLoader classLoader = this.getClass().getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        objectMapper.registerModules(securityModules);
        objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        objectMapper.registerModule(new OAuth2Module());
        objectMapper.setHandlerInstantiator(new SpringHandlerInstantiator(beanFactory));
    }

    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }

    public void setObjectMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        String clientId = authorization.getRegisteredClientId();
        RegisteredClient registeredClient = clientRepository.findById(clientId);
        Assert.notNull(registeredClient, "Registered client must not be null");

        Duration codeTtl = registeredClient.getTokenSettings().getAuthorizationCodeTimeToLive();
        Duration accessTokenTtl = registeredClient.getTokenSettings().getAccessTokenTimeToLive();
        Duration refreshTokenTtl = registeredClient.getTokenSettings().getRefreshTokenTimeToLive();
        // Use state-time-to-live in token settings. Or else, defaults to access token TTL
        Duration stateTtl = Optional.ofNullable((Duration) registeredClient.getTokenSettings().getSetting("state-time-to-live"))
            .orElse(accessTokenTtl);
        // Use the max TTL
        Duration max = Collections.max(Arrays.asList(codeTtl, accessTokenTtl, refreshTokenTtl, stateTtl));
        Duration authorizationTtl = max;
        Duration correlationsTtl = max;

        List<String> keys = new ArrayList<>();
        keys.add(getIdToAuthorizationKey(authorization.getId()));
        keys.add(getIdToCorrelations(authorization.getId()));
        Optional.ofNullable(authorization.getAttribute(OAuth2ParameterNames.STATE)).ifPresent(token -> {
            String stateToAuthorization = getStateToAuthorization((String) token);
            keys.add(stateToAuthorization);
        });
        Optional.ofNullable(authorization.getToken(OAuth2AuthorizationCode.class)).ifPresent(token -> {
            String codeToAuthorization = getCodeToAuthorization(token.getToken().getTokenValue());
            keys.add(codeToAuthorization);
        });
        Optional.ofNullable(authorization.getAccessToken()).ifPresent(token -> {
            String accessToAuthorization = getAccessToAuthorization(token.getToken().getTokenValue());
            keys.add(accessToAuthorization);
        });
        Optional.ofNullable(authorization.getRefreshToken()).ifPresent(token -> {
            String refreshToAuthorization = getRefreshToAuthorization(token.getToken().getTokenValue());
            keys.add(refreshToAuthorization);
        });

        redisOperations.execute(saveScript, keys, write(authorization), authorization.getId(),
            String.valueOf(stateTtl.getSeconds()), String.valueOf(codeTtl.getSeconds()),
            String.valueOf(accessTokenTtl.getSeconds()), String.valueOf(refreshTokenTtl.getSeconds()),
            String.valueOf(authorizationTtl.getSeconds()), String.valueOf(correlationsTtl.getSeconds()));
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        List<String> keys = new ArrayList<>();

        keys.add(getIdToAuthorizationKey(authorization.getId()));
        Optional.ofNullable(redisOperations.opsForSet().members(getIdToCorrelations(authorization.getId())))
            .ifPresent(keys::addAll);
        keys.add(getIdToCorrelations(authorization.getId()));

        redisOperations.delete(keys);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return Optional.ofNullable(redisOperations.opsForValue().get(getIdToAuthorizationKey(id))).map(this::parse)
            .orElse(null);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");
        if (tokenType == null) {
            return Optional.ofNullable(redisOperations.opsForValue().get(getStateToAuthorization(token)))
                .or(() -> Optional.ofNullable(redisOperations.opsForValue().get(getCodeToAuthorization(token))))
                .or(() -> Optional.ofNullable(redisOperations.opsForValue().get(getAccessToAuthorization(token))))
                .or(() -> Optional.ofNullable(redisOperations.opsForValue().get(getRefreshToAuthorization(token))))
                .map(this::findById).orElse(null);
        } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            return Optional.ofNullable(redisOperations.opsForValue().get(getStateToAuthorization(token)))
                .map(this::findById).orElse(null);
        } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            return Optional.ofNullable(redisOperations.opsForValue().get(getCodeToAuthorization(token)))
                .map(this::findById).orElse(null);
        } else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            return Optional.ofNullable(redisOperations.opsForValue().get(getAccessToAuthorization(token)))
                .map(this::findById).orElse(null);
        } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            return Optional.ofNullable(redisOperations.opsForValue().get(getRefreshToAuthorization(token)))
                .map(this::findById).orElse(null);
        }
        return null;
    }

    private String getIdToAuthorizationKey(String authorizationId) {
        return prefix + ID_TO_AUTHORIZATION + authorizationId;
    }

    private String getStateToAuthorization(String state) {
        return prefix + STATE_TO_AUTHORIZATION + generateKey(state);
    }

    private String getCodeToAuthorization(String code) {
        return prefix + CODE_TO_AUTHORIZATION + generateKey(code);
    }

    private String getAccessToAuthorization(String accessToken) {
        return prefix + ACCESS_TO_AUTHORIZATION + generateKey(accessToken);
    }

    private String getRefreshToAuthorization(String refreshToken) {
        return prefix + REFRESH_TO_AUTHORIZATION + generateKey(refreshToken);
    }

    private String getIdToCorrelations(String authorizationId) {
        return prefix + ID_TO_CORRELATIONS + authorizationId;
    }

    protected String generateKey(String rawKey) {
        byte[] bytes = digest.digest(rawKey.getBytes(StandardCharsets.UTF_8));
        return String.format("%032x", new BigInteger(1, bytes));
    }

    private String write(Object data) {
        try {
            return this.objectMapper.writeValueAsString(data);
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

    private OAuth2Authorization parse(String data) {
        try {
            return this.objectMapper.readValue(data, new TypeReference<>() {
            });
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

}
