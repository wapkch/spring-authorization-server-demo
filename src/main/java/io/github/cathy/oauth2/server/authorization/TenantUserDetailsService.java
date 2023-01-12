package io.github.cathy.oauth2.server.authorization;

import com.zhongan.multitenancy.context.DefaultTenantContext;

import java.util.Collections;
import java.util.HashSet;

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
        TenantUserDetails userDetails = new TenantUserDetails(1L, "user1",
            PasswordEncoderFactories.createDelegatingPasswordEncoder().encode("password"),
            true, false, false, false, new HashSet<>());
        DefaultTenantContext context = new DefaultTenantContext("testTenant");
        context.addAttribute("x-za-region", "testRegion");
        userDetails.setTenantContext(context);
        return userDetails;
    }

}
