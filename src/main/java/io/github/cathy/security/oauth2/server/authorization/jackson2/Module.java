package io.github.cathy.security.oauth2.server.authorization.jackson2;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.zhongan.multitenancy.context.DefaultTenantContext;
import com.zhongan.multitenancy.context.TenantContext;

import java.time.Duration;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;

import org.springframework.security.jackson2.SecurityJackson2Modules;

public class Module extends SimpleModule {

    public Module() {
        super(Module.class.getName(), new Version(1, 0, 0, null, null, null));
    }

    @Override
    public void setupModule(SetupContext context) {
        SecurityJackson2Modules.enableDefaultTyping(context.getOwner());

        context.setMixInAnnotations(DefaultTenantContext.class, TenantContextMixin.class);
    }

}
