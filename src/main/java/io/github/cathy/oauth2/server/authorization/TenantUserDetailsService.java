package io.github.cathy.oauth2.server.authorization;

import com.google.common.collect.Sets;
import com.zhongan.multitenancy.context.DefaultTenantContext;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.InvalidDataAccessApiUsageException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Slf4j
@Service
public class TenantUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String usernameParam) {
        Map<String, Object> attributes1 = new HashMap<>();
        attributes1.put("attr1", "value1");
        AttributeGrantedAuthority authority1 = new AttributeGrantedAuthority("perm1", attributes1);

        Map<String, Object> attributes2 = new HashMap<>();
        attributes2.put("attr11", "value11");
        AttributeGrantedAuthority authority2 = new AttributeGrantedAuthority("perm2", attributes2);

        TenantUserDetails userDetails = new TenantUserDetails(Long.MAX_VALUE - 1, "user1",
            PasswordEncoderFactories.createDelegatingPasswordEncoder().encode("password"),
            true, false, false, false, Sets.newHashSet(authority1, authority2));
        DefaultTenantContext context = new DefaultTenantContext("testTenant");
        context.addAttribute("x-za-region", "testRegion");
        userDetails.setTenantContext(context);
        return userDetails;
    }

}
