package io.github.cathy.security.oauth2.server.authorization.jackson2;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.zhongan.multitenancy.context.TenantContext;

import java.util.Map;
import java.util.Set;


@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonDeserialize(using = TenantUserDeserializer.class)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE,
    isGetterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class TenantUserDetailsMixin {

//    @JsonCreator
//    TenantUserDetailsMixin(@JsonProperty("userId") Long userId, @JsonProperty("username") String username,
//                           @JsonProperty("password") String password, @JsonProperty("enabled") boolean enabled,
//                           @JsonProperty("locked") boolean locked, @JsonProperty("accountExpired") boolean accountExpired,
//                           @JsonProperty("credentialsExpired") boolean credentialsExpired,
//                           @JsonProperty("authorities") Set<GrantedAuthority> authorities) {
//    }
//
//    @JsonProperty("tenantContext")
//    TenantContext tenantContext;

}
