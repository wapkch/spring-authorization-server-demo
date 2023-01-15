package io.github.cathy.oauth2.server.authorization;

import com.zhongan.multitenancy.context.TenantAware;
import com.zhongan.multitenancy.context.TenantContext;

import java.util.Collection;
import java.util.Set;

import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class TenantUserDetails implements UserDetails, CredentialsContainer, TenantAware {

    private final Long userId;

    private final String username;

    private String password;

    private final boolean enabled;

    private final boolean locked;

    private final boolean accountExpired;

    private final boolean credentialsExpired;

    private TenantContext tenantContext;

    private final Set<AttributeGrantedAuthority> authorities;

    public TenantUserDetails(Long userId, String username, String password,
                             boolean enabled, boolean locked, boolean accountExpired, boolean credentialsExpired,
                             Set<AttributeGrantedAuthority> authorities) {
        this.userId = userId;
        this.username = username;
        this.password = password;
        this.enabled = enabled;
        this.locked = locked;
        this.accountExpired = accountExpired;
        this.credentialsExpired = credentialsExpired;
        this.authorities = authorities;
    }

    public Long getUserId() {
        return userId;
    }

    public TenantContext getTenantContext() {
        return tenantContext;
    }

    @Override
    public void setTenantContext(TenantContext tenantContext) {
        this.tenantContext = tenantContext;
    }

    @Override
    public Collection<AttributeGrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return !accountExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !locked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return !credentialsExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public void eraseCredentials() {
        password = "";
    }

}
