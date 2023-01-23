package sample;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gargoylesoftware.htmlunit.HttpMethod;
import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebRequest;
import com.gargoylesoftware.htmlunit.WebResponse;
import com.gargoylesoftware.htmlunit.html.HtmlButton;
import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.google.common.base.Splitter;

import java.io.IOException;
import java.net.URL;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.util.UriComponentsBuilder;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.lifecycle.Startables;
import org.testcontainers.utility.DockerImageName;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
@TestPropertySource(properties = {"server.port=9000"})
@AutoConfigureMockMvc
public class AuthorizationServerTests {
	private static final String REDIRECT_URI = "http://127.0.0.1:8080/authorized";

	private static final String AUTHORIZATION_REQUEST = UriComponentsBuilder
			.fromPath("/oauth2/authorize")
			.queryParam("response_type", "code")
			.queryParam("client_id", "messaging-client")
			.queryParam("scope", OidcScopes.OPENID+" message.read")
			.queryParam("state", "some-state")
			.queryParam("redirect_uri", REDIRECT_URI)
			.toUriString();

	@Autowired
	private WebClient webClient;

	protected static final GenericContainer<?> redis =
		new GenericContainer<>(DockerImageName.parse("redis:7.0.5-alpine")).withExposedPorts(6379);

	@DynamicPropertySource
	protected static void overridePropertiesInternal(DynamicPropertyRegistry registry) {
		Startables.deepStart(redis).join();

		registry.add("spring.data.redis.host", redis::getHost);
		registry.add("spring.data.redis.port", redis::getFirstMappedPort);
	}

	@BeforeEach
	public void setUp() {
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(true);
		this.webClient.getOptions().setRedirectEnabled(true);
		this.webClient.getCookieManager().clearCookies();	// log out
	}

	@AfterAll
	static void afterAllBase() {
		redis.stop();
	}

	@Test
	public void testDefault() throws IOException {
		// Authorization Request
		HtmlPage page = this.webClient.getPage(AUTHORIZATION_REQUEST);
		assertLoginPage(page);

		// Login
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
		this.webClient.getOptions().setRedirectEnabled(false);
		WebResponse signInResponse = signIn(page, "user1", "password").getWebResponse();
		String location = signInResponse.getResponseHeaderValue("location");

		// Authorization code callback
		WebResponse webResponse = this.webClient.getPage(location).getWebResponse();
		String authzCodeCallback = webResponse.getResponseHeaderValue("location");
		String code = getParam(authzCodeCallback, "code");

		// Token Request
		URL url = new URL("http://localhost:9000/oauth2/token");
		WebRequest requestSettings = new WebRequest(url, HttpMethod.POST);
		requestSettings.setAdditionalHeader("Authorization", "Basic bWVzc2FnaW5nLWNsaWVudDpzZWNyZXQ=");
		requestSettings.setAdditionalHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
		requestSettings.setRequestBody("grant_type=authorization_code&redirect_uri=http://127.0.0.1:8080/authorized&scope=message.read&code=" + code);
		WebResponse tokenResponse = webClient.getPage(requestSettings).getWebResponse();
		Map<String, Object> token = new ObjectMapper().readValue(tokenResponse.getContentAsString(), new TypeReference<>() {
		});
		String accessToken = (String) token.get("access_token");
		assertThat(accessToken).isNotNull();

		// Token Introspection Request
		URL introspectUrl = new URL("http://localhost:9000/oauth2/introspect");
		WebRequest request = new WebRequest(introspectUrl, HttpMethod.POST);
		request.setAdditionalHeader("Authorization", "Basic bWVzc2FnaW5nLWNsaWVudDpzZWNyZXQ=");
		request.setAdditionalHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
		request.setRequestBody("token=" + accessToken);
		WebResponse tokenIntrospectionResponse = webClient.getPage(request).getWebResponse();
		Map<String, Object> tokenIntrospection = new ObjectMapper().readValue(tokenIntrospectionResponse.getContentAsString(), new TypeReference<>() {
		});
		assertThat(tokenIntrospection.get("sub")).isEqualTo("user1");
	}

	@Test
	public void whenLoginFailsThenDisplayBadCredentials() throws IOException {
		HtmlPage page = this.webClient.getPage("/");

		HtmlPage loginErrorPage = signIn(page, "user1", "wrong-password");

		HtmlElement alert = loginErrorPage.querySelector("div[role=\"alert\"]");
		assertThat(alert).isNotNull();
		assertThat(alert.getTextContent()).isEqualTo("Bad credentials");
	}

	private static <P extends Page> P signIn(HtmlPage page, String username, String password) throws IOException {
		HtmlInput usernameInput = page.querySelector("input[name=\"username\"]");
		HtmlInput passwordInput = page.querySelector("input[name=\"password\"]");
		HtmlButton signInButton = page.querySelector("button");

		usernameInput.type(username);
		passwordInput.type(password);
		return signInButton.click();
	}

	private static void assertLoginPage(HtmlPage page) {
		assertThat(page.getUrl().toString()).endsWith("/login");

		HtmlInput usernameInput = page.querySelector("input[name=\"username\"]");
		HtmlInput passwordInput = page.querySelector("input[name=\"password\"]");
		HtmlButton signInButton = page.querySelector("button");

		assertThat(usernameInput).isNotNull();
		assertThat(passwordInput).isNotNull();
		assertThat(signInButton.getTextContent()).isEqualTo("Sign in");
	}

	private String getParam(String url, String name) {
		String params = url.substring(url.indexOf("?") + 1);
		Map<String, String> split = Splitter.on("&").withKeyValueSeparator("=").split(params);
		return split.get(name);
	}

}
