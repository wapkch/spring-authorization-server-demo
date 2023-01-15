package io.github.cathy.oauth2.server.authorization;

import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import org.springframework.security.core.GrantedAuthority;

@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(of = "permission")
public class AttributeGrantedAuthority implements GrantedAuthority {

    private String permission;

    private Map<String, Object> attributes;

    @Override
    public String getAuthority() {
        return permission;
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

}
