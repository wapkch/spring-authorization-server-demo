package sample.redis;

import sample.jackson2.OAuth2AuthorizationModule;

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
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import lombok.Setter;

import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.data.redis.core.RedisOperations;
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
import org.springframework.util.CollectionUtils;

public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private static final String ID_TO_AUTHORIZATION = "id_to_authorization:";

    private static final String STATE_TO_AUTHORIZATION = "state_to_authorization:";

    private static final String CODE_TO_AUTHORIZATION = "code_to_authorization:";

    private static final String ACCESS_TO_AUTHORIZATION = "access_to_authorization:";

    private static final String REFRESH_TO_AUTHORIZATION = "refresh_to_authorization:";

    private static final String ID_TO_CORRELATIONS = "id_to_correlations:";

    private static final String UID_TO_AUTHORIZATIONS = "uid_to_authorizations:";

    private static final String CID_TO_AUTHORIZATIONS = "cid_to_authorizations:";

    private static final MessageDigest DIGEST;

    private final RedisOperations<String, String> redisOperations;

    private final RegisteredClientRepository clientRepository;

    @Setter
    private ObjectMapper objectMapper = new ObjectMapper();

    @Setter
    private String prefix = "";

    static {
        try {
            DIGEST = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public RedisOAuth2AuthorizationService(RedisOperations<String, String> redisOperations,
                                           RegisteredClientRepository clientRepository,
                                           AutowireCapableBeanFactory beanFactory) {
        Assert.notNull(redisOperations, "redisOperations mut not be null");
        this.redisOperations = redisOperations;
        this.clientRepository = clientRepository;

        ClassLoader classLoader = this.getClass().getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        objectMapper.registerModules(securityModules);
        objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        objectMapper.registerModule(new OAuth2AuthorizationModule());
        objectMapper.setHandlerInstantiator(new SpringHandlerInstantiator(beanFactory));
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        final String clientId = authorization.getRegisteredClientId();
        RegisteredClient registeredClient = clientRepository.findById(clientId);
        Assert.notNull(registeredClient, "Registered client must not be null");

        Duration codeTtl = registeredClient.getTokenSettings().getAuthorizationCodeTimeToLive();
        Duration accessTokenTtl = registeredClient.getTokenSettings().getAccessTokenTimeToLive();
        Duration refreshTokenTtl = registeredClient.getTokenSettings().getRefreshTokenTimeToLive();
        Duration stateTtl = codeTtl;
        Duration max = authorization.getRefreshToken() != null ?
            accessTokenTtl : Collections.max(Arrays.asList(accessTokenTtl, refreshTokenTtl));
        Duration authorizationTtl = max;
        Duration correlationsTtl = max;
        Duration uidTtl = max;
        Duration cidTtl = max;

        final String authorizationId = authorization.getId();
        final String idToAuthorizationKey = getIdToAuthorizationKey(authorizationId);
        final String cidToAuthorizationsKey = getCidToAuthorizations(clientId);

        redisOperations.opsForValue().set(idToAuthorizationKey, write(authorization),
            authorizationTtl.getSeconds(), TimeUnit.SECONDS);

        redisOperations.opsForSet().add(cidToAuthorizationsKey, authorizationId);
        redisOperations.expire(cidToAuthorizationsKey, cidTtl);

        Set<String> correlationValues = new HashSet<>();
        Optional.ofNullable(authorization.getAttribute(OAuth2ParameterNames.STATE)).ifPresent(token -> {
            final String stateToAuthorizationKey = getStateToAuthorization((String) token);
            redisOperations.opsForValue().set(stateToAuthorizationKey, authorizationId,
                stateTtl.getSeconds(), TimeUnit.SECONDS);
            correlationValues.add(stateToAuthorizationKey);
        });
        Optional.ofNullable(authorization.getToken(OAuth2AuthorizationCode.class)).ifPresent(token -> {
            final String codeToAuthorizationKey = getCodeToAuthorization(token.getToken().getTokenValue());
            redisOperations.opsForValue().set(codeToAuthorizationKey, authorizationId,
                codeTtl.getSeconds(), TimeUnit.SECONDS);
            correlationValues.add(codeToAuthorizationKey);
        });
        Optional.ofNullable(authorization.getAccessToken()).ifPresent(token -> {
            final String accessToAuthorization = getAccessToAuthorization(token.getToken().getTokenValue());
            redisOperations.opsForValue().set(accessToAuthorization, authorizationId,
                accessTokenTtl.getSeconds(), TimeUnit.SECONDS);
            correlationValues.add(accessToAuthorization);
        });
        Optional.ofNullable(authorization.getRefreshToken()).ifPresent(token -> {
            final String refreshToAuthorization = getRefreshToAuthorization(token.getToken().getTokenValue());
            redisOperations.opsForValue().set(refreshToAuthorization, authorizationId,
                refreshTokenTtl.getSeconds(), TimeUnit.SECONDS);
            correlationValues.add(refreshToAuthorization);
        });
        if (!CollectionUtils.isEmpty(correlationValues)) {
            redisOperations.opsForSet().add(getIdToCorrelations(authorizationId), correlationValues.toArray(String[]::new));
            redisOperations.expire(getIdToCorrelations(authorizationId), correlationsTtl);
        }
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        List<String> keysToRemove = new ArrayList<>();
        keysToRemove.add(getIdToAuthorizationKey(authorization.getId()));
        keysToRemove.add(getIdToCorrelations(authorization.getId()));
        Optional.ofNullable(redisOperations.opsForSet().members(getIdToCorrelations(authorization.getId())))
            .ifPresent(keysToRemove::addAll);
        redisOperations.delete(keysToRemove);

        final String clientId = authorization.getRegisteredClientId();
        redisOperations.opsForSet().remove(getCidToAuthorizations(clientId), authorization.getId());
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

    public String getCidToAuthorizations(String clientId) {
        return prefix + CID_TO_AUTHORIZATIONS + clientId;
    }

    protected static String generateKey(String rawKey) {
        byte[] bytes = DIGEST.digest(rawKey.getBytes(StandardCharsets.UTF_8));
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
