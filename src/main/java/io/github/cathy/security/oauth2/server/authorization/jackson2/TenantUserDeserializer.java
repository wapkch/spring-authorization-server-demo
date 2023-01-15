/*
 * Copyright 2015-2018 the original author or authors.
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

package io.github.cathy.security.oauth2.server.authorization.jackson2;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import com.zhongan.multitenancy.context.TenantContext;

import io.github.cathy.oauth2.server.authorization.AttributeGrantedAuthority;
import io.github.cathy.oauth2.server.authorization.TenantUserDetails;

import java.io.IOException;
import java.util.Set;

import org.springframework.security.core.userdetails.User;

class TenantUserDeserializer extends JsonDeserializer<TenantUserDetails> {

	private static final TypeReference<Set<AttributeGrantedAuthority>> ATTRIBUTE_GRANTED_AUTHORITY_SET = new TypeReference<Set<AttributeGrantedAuthority>>() {
	};

	private static final TypeReference<TenantContext> TENANT_CONTEXT_TYPE_REFERENCE = new TypeReference<TenantContext>() {
	};

	/**
	 * This method will create {@link User} object. It will ensure successful object
	 * creation even if password key is null in serialized json, because credentials may
	 * be removed from the {@link User} by invoking {@link User#eraseCredentials()}. In
	 * that case there won't be any password key in serialized json.
	 * @param jp the JsonParser
	 * @param ctxt the DeserializationContext
	 * @return the user
	 * @throws IOException if a exception during IO occurs
	 * @throws JsonProcessingException if an error during JSON processing occurs
	 */
	@Override
	public TenantUserDetails deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException, JsonProcessingException {
		ObjectMapper mapper = (ObjectMapper) jp.getCodec();
		JsonNode jsonNode = mapper.readTree(jp);
		Set<AttributeGrantedAuthority> authorities = mapper.convertValue(jsonNode.get("authorities"),
			ATTRIBUTE_GRANTED_AUTHORITY_SET);

		TenantContext tenantContext = mapper.convertValue(jsonNode.get("tenantContext"),
			TENANT_CONTEXT_TYPE_REFERENCE);
		JsonNode passwordNode = readJsonNode(jsonNode, "password");
		Long userId = readJsonNode(jsonNode, "userId").asLong();
		String username = readJsonNode(jsonNode, "username").asText();
		String password = passwordNode.asText("");
		boolean enabled = readJsonNode(jsonNode, "enabled").asBoolean();
		boolean accountExpired = readJsonNode(jsonNode, "accountExpired").asBoolean();
		boolean credentialsExpired = readJsonNode(jsonNode, "credentialsExpired").asBoolean();
		boolean locked = readJsonNode(jsonNode, "locked").asBoolean();

		TenantUserDetails result = new TenantUserDetails(userId, username, password,
			enabled, locked, accountExpired, credentialsExpired, authorities);
		result.setTenantContext(tenantContext);
		if (passwordNode.asText(null) == null) {
			result.eraseCredentials();
		}
		return result;
	}

	private JsonNode readJsonNode(JsonNode jsonNode, String field) {
		return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
	}

}
