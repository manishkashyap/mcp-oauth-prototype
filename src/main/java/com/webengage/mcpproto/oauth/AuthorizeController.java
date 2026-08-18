package com.webengage.mcpproto.oauth;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.webengage.mcpproto.oauth.model.AuthorizationCode;
import com.webengage.mcpproto.oauth.model.PendingAuthorizationRequest;
import com.webengage.mcpproto.oauth.model.RegisteredClient;
import com.webengage.mcpproto.oauth.store.OAuthStore;

import jakarta.servlet.http.HttpServletResponse;

/**
 * GET /oauth2/authorize validates everything BEFORE trusting redirect_uri for anything -
 * same ordering discipline as the fix already shipped in WebEngage's AuthorizationAction:
 * unknown client and bad redirect_uri both render in-page, never redirect to the caller-
 * supplied URI. Only once redirect_uri is confirmed registered do later failures (bad PKCE,
 * wrong resource, wrong response_type) redirect back with an error param.
 */
@Controller
@RequestMapping("/oauth2")
public class AuthorizeController {

	private static final Set<String> KNOWN_SCOPES = Set.of("campaigns:read", "integrations:read");
	private static final List<String> FAKE_PUBLISHERS = List.of("acme-corp", "globex-inc");

	private final ClientResolver clientResolver;
	private final OAuthStore store;

	@Value("${webengage.oauth.mcp-resource}")
	private String mcpResource;

	public AuthorizeController(ClientResolver clientResolver, OAuthStore store) {
		this.clientResolver = clientResolver;
		this.store = store;
	}

	@GetMapping("/authorize")
	public String authorize(
			@RequestParam(required = false) String response_type,
			@RequestParam(required = false) String client_id,
			@RequestParam(required = false) String redirect_uri,
			@RequestParam(required = false) String code_challenge,
			@RequestParam(required = false) String code_challenge_method,
			@RequestParam(required = false) String resource,
			@RequestParam(required = false) String scope,
			@RequestParam(required = false) String state,
			Model model, HttpServletResponse response) {

		if (client_id == null || client_id.isBlank()) {
			return renderError(model, response, "invalid_request", "Missing client_id");
		}

		Optional<RegisteredClient> clientOpt = clientResolver.resolve(client_id);
		if (clientOpt.isEmpty()) {
			return renderError(model, response, "invalid_client",
					"Unknown client_id, or its CIMD document could not be fetched/validated");
		}
		RegisteredClient client = clientOpt.get();

		if (redirect_uri == null || !client.redirectUriAllowed(redirect_uri)) {
			return renderError(model, response, "invalid_request",
					"redirect_uri is missing or is not exactly one of this client's registered redirect_uris");
		}

		// redirect_uri is trusted from here on.
		if (!"code".equals(response_type)) {
			return redirectWithError(redirect_uri, state, "unsupported_response_type",
					"Only response_type=code is supported (no implicit flow)");
		}
		if (code_challenge == null || code_challenge.isBlank() || !Pkce.METHOD_S256.equals(code_challenge_method)) {
			return redirectWithError(redirect_uri, state, "invalid_request",
					"PKCE code_challenge with code_challenge_method=S256 is required");
		}
		if (resource == null || !mcpResource.equals(resource)) {
			return redirectWithError(redirect_uri, state, "invalid_target",
					"resource must be exactly " + mcpResource);
		}

		Set<String> requestedScope = parseScope(scope);

		PendingAuthorizationRequest pending = new PendingAuthorizationRequest(
				client.getClientId(), client.getClientName(), redirect_uri, resource,
				requestedScope, code_challenge, code_challenge_method, state);
		String requestId = store.storePendingRequest(pending);

		model.addAttribute("requestId", requestId);
		model.addAttribute("clientName", client.getClientName());
		model.addAttribute("scopes", requestedScope);
		model.addAttribute("publishers", FAKE_PUBLISHERS);
		return "consent";
	}

	@PostMapping("/authorize/approve")
	public String approve(
			@RequestParam String requestId,
			@RequestParam(required = false) String username,
			@RequestParam(required = false) String publisherId,
			@RequestParam(required = false) String decision,
			Model model, HttpServletResponse response) {

		PendingAuthorizationRequest pending = store.takePendingRequest(requestId);
		if (pending == null) {
			return renderError(model, response, "invalid_request",
					"This authorization request has expired or was already used - restart the connector setup.");
		}

		if (!"approve".equals(decision)) {
			Map<String, String> params = new LinkedHashMap<>();
			params.put("error", "access_denied");
			if (pending.getState() != null) {
				params.put("state", pending.getState());
			}
			return "redirect:" + appendQuery(pending.getRedirectUri(), params);
		}

		String subject = (username == null || username.isBlank()) ? "test-user@webengage.com" : username;
		String publisher = (publisherId == null || publisherId.isBlank()) ? FAKE_PUBLISHERS.get(0) : publisherId;

		String code = OAuthStore.randomToken();
		AuthorizationCode authCode = new AuthorizationCode(
				code, pending.getClientId(), pending.getRedirectUri(), pending.getResource(),
				pending.getScope(), pending.getCodeChallenge(), pending.getCodeChallengeMethod(),
				subject, publisher, Instant.now().plusSeconds(60));
		store.storeCode(authCode);

		Map<String, String> params = new LinkedHashMap<>();
		params.put("code", code);
		if (pending.getState() != null) {
			params.put("state", pending.getState());
		}
		return "redirect:" + appendQuery(pending.getRedirectUri(), params);
	}

	private Set<String> parseScope(String scope) {
		if (scope == null || scope.isBlank()) {
			return KNOWN_SCOPES;
		}
		Set<String> requested = new LinkedHashSet<>();
		for (String s : scope.split(" ")) {
			if (KNOWN_SCOPES.contains(s)) {
				requested.add(s);
			}
		}
		return requested.isEmpty() ? KNOWN_SCOPES : requested;
	}

	private String renderError(Model model, HttpServletResponse response, String error, String description) {
		response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
		model.addAttribute("error", error);
		model.addAttribute("errorDescription", description);
		return "error";
	}

	private String redirectWithError(String redirectUri, String state, String error, String description) {
		Map<String, String> params = new LinkedHashMap<>();
		params.put("error", error);
		params.put("error_description", description);
		if (state != null) {
			params.put("state", state);
		}
		return "redirect:" + appendQuery(redirectUri, params);
	}

	private String appendQuery(String uri, Map<String, String> params) {
		StringBuilder sb = new StringBuilder(uri);
		sb.append(uri.contains("?") ? "&" : "?");
		boolean first = true;
		for (Map.Entry<String, String> entry : params.entrySet()) {
			if (!first) {
				sb.append("&");
			}
			first = false;
			sb.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8));
			sb.append("=");
			sb.append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
		}
		return sb.toString();
	}
}
