/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.cathy.config;

import com.zhongan.multitenancy.context.DefaultTenantContext;

import io.github.cathy.oauth2.server.authorization.TenantUserDetails;

import java.util.Collections;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * @author Joe Grandja
 * @since 0.1.0
 */
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

	// @formatter:off
	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(authorize ->
				authorize.anyRequest().authenticated()
			)
			.formLogin(withDefaults());
		return http.build();
	}
	// @formatter:on

	// @formatter:off
//	@Bean
//	UserDetailsService users() {
//		TenantUserDetails userDetails = new TenantUserDetails(1L, "user1",
//			PasswordEncoderFactories.createDelegatingPasswordEncoder().encode("password"),
//			true, false, false, false, Collections.emptySet());
//		DefaultTenantContext context = new DefaultTenantContext("testTenant");
//		context.addAttribute("x-za-region", "testRegion");
//		userDetails.setTenantContext(context);
//
////		UserDetails user = User.withDefaultPasswordEncoder()
////				.username("user1")
////				.password("password")
////				.roles("USER")
////				.build();
//		return new InMemoryUserDetailsManager(userDetails);
//	}
//	// @formatter:on

}
