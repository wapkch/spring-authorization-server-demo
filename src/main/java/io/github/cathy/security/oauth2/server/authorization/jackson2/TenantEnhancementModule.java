package io.github.cathy.security.oauth2.server.authorization.jackson2;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.zhongan.multitenancy.context.DefaultTenantContext;

import io.github.cathy.oauth2.server.authorization.AttributeGrantedAuthority;
import io.github.cathy.oauth2.server.authorization.TenantUserDetails;

import org.springframework.security.jackson2.SecurityJackson2Modules;

public class TenantEnhancementModule extends SimpleModule {

    public TenantEnhancementModule() {
        super(TenantEnhancementModule.class.getName(), new Version(1, 0, 0, null, null, null));
    }

    @Override
    public void setupModule(SetupContext context) {
        SecurityJackson2Modules.enableDefaultTyping(context.getOwner());

        context.setMixInAnnotations(DefaultTenantContext.class, TenantContextMixin.class);
        context.setMixInAnnotations(TenantUserDetails.class, TenantUserDetailsMixin.class);
        context.setMixInAnnotations(Long.class, LongMixin.class);
        context.setMixInAnnotations(AttributeGrantedAuthority.class, AttributeGrantedAuthorityMixin.class);
    }

}
