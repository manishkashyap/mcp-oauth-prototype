package com.webengage.mcpproto.oauth;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.webengage.mcpproto.config.OAuthProperties;
import com.webengage.mcpproto.oauth.model.AccessToken;
import com.webengage.mcpproto.oauth.model.AuthorizationCode;
import com.webengage.mcpproto.oauth.model.RefreshToken;
import com.webengage.mcpproto.oauth.model.RegisteredClient;
import com.webengage.mcpproto.oauth.store.OAuthStore;

/**
 * The endpoint the real WebEngage token() method is missing today: standards-shaped JSON on
 * success, real non-200 HTTP status + RFC 6749 error codes on failure. This is the piece
 * flagged as highest-priority in MCP_OAUTH_IMPLEMENTATION.md - a standard OAuth client
 * library can't complete the flow without it, independent of PKCE or scopes.
 *
 * Accepts application/x-www-form-urlencoded per RFC 6749 5.1 (the default for
 * {@code @RequestParam} on a POST body - no special config needed).
 */
@RestController
@RequestMapping("/oauth2")
public class TokenController {

	private final OAuthStore store;
	private final ClientResolver clientResolver;
	private final OAuthProperties properties;

	public TokenController(OAuthStore store, ClientResolver clientResolver, OAuthProperties properties) {
		this.store = store;
		this.clientResolver = clientResolver;
		this.properties = properties;
	}

	@PostMapping(value = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
	public ResponseEntity<Map<String, Object>> token(
			@RequestParam(required = false) String grant_type,
			@RequestParam(required = false) String code,
			@RequestParam(required = false) String redirect_uri,
			@RequestParam(required = false) String client_id,
			@RequestParam(required = false) String client_secret,
			@RequestParam(required = false) String code_verifier,
			@RequestParam(required = false) String resource,
			@RequestParam(required = false) String refresh_token) {

		if (grant_type == null || grant_type.isBlank()) {
			return error(HttpStatus.BAD_REQUEST, "invalid_request", "Missing grant_type");
		}

		Optional<RegisteredClient> clientOpt = clientResolver.resolve(client_id);
		if (clientOpt.isEmpty()) {
			return error(HttpStatus.BAD_REQUEST, "invalid_client", "Unknown or unresolvable client_id");
		}
		RegisteredClient client = clientOpt.get();

		if (client.isConfidential() && (client_secret == null || !client_secret.equals(client.getClientSecret()))) {
			return error(HttpStatus.BAD_REQUEST, "invalid_client", "Missing or incorrect client_secret");
		}

		return switch (grant_type) {
			case "authorization_code" -> handleAuthorizationCode(client, code, redirect_uri, code_verifier, resource);
			case "refresh_token" -> handleRefreshToken(client, refresh_token);
			default -> error(HttpStatus.BAD_REQUEST, "unsupported_grant_type",
					"grant_type must be authorization_code or refresh_token");
		};
	}

	private ResponseEntity<Map<String, Object>> handleAuthorizationCode(RegisteredClient client, String code,
			String redirectUri, String codeVerifier, String resource) {

		if (code == null || redirectUri == null || resource == null) {
			return error(HttpStatus.BAD_REQUEST, "invalid_request", "Missing code, redirect_uri, or resource");
		}

		AuthorizationCode authCode = store.getCode(code);
		if (authCode == null) {
			return error(HttpStatus.BAD_REQUEST, "invalid_grant", "Unknown authorization code");
		}
		// Atomic single-use check FIRST - a second, racing redemption attempt must fail here
		// even if every other field would have validated fine.
		if (!authCode.tryConsume()) {
			return error(HttpStatus.BAD_REQUEST, "invalid_grant", "Authorization code already used");
		}
		if (authCode.isExpired()) {
			return error(HttpStatus.BAD_REQUEST, "invalid_grant", "Authorization code expired");
		}
		if (!authCode.getClientId().equals(client.getClientId())) {
			return error(HttpStatus.BAD_REQUEST, "invalid_grant", "Code was issued to a different client");
		}
		if (!authCode.getRedirectUri().equals(redirectUri)) {
			return error(HttpStatus.BAD_REQUEST, "invalid_grant",
					"redirect_uri does not match the one used at authorization time");
		}
		if (!authCode.getResource().equals(resource)) {
			return error(HttpStatus.BAD_REQUEST, "invalid_target",
					"resource does not match the one used at authorization time");
		}
		if (!Pkce.verify(codeVerifier, authCode.getCodeChallenge(), authCode.getCodeChallengeMethod())) {
			return error(HttpStatus.BAD_REQUEST, "invalid_grant", "code_verifier does not match code_challenge");
		}

		return issueTokens(client, authCode.getSubject(), authCode.getPublisherId(), authCode.getResource(),
				authCode.getScope(), true);
	}

	private ResponseEntity<Map<String, Object>> handleRefreshToken(RegisteredClient client, String refreshTokenValue) {
		if (refreshTokenValue == null || refreshTokenValue.isBlank()) {
			return error(HttpStatus.BAD_REQUEST, "invalid_request", "Missing refresh_token");
		}
		RefreshToken refreshToken = store.getRefreshToken(refreshTokenValue);
		if (refreshToken == null || !refreshToken.getClientId().equals(client.getClientId())) {
			// RFC 6749-compliant code, not a custom one - Claude's docs specifically call out
			// that it only retries refresh on invalid_grant, not on an ad-hoc error string.
			return error(HttpStatus.BAD_REQUEST, "invalid_grant", "Unknown or mismatched refresh_token");
		}
		// Non-rotating by design for this prototype - same refresh_token stays valid,
		// so we don't mint or return a new one here.
		return issueTokens(client, refreshToken.getSubject(), refreshToken.getPublisherId(),
				refreshToken.getResource(), refreshToken.getScope(), false);
	}

	private ResponseEntity<Map<String, Object>> issueTokens(RegisteredClient client, String subject,
			String publisherId, String resource, Set<String> scope, boolean issueRefreshToken) {

		String accessTokenValue = OAuthStore.randomToken();
		Instant expiresAt = Instant.now().plusSeconds(properties.getAccessTokenTtlSeconds());
		store.storeAccessToken(new AccessToken(accessTokenValue, client.getClientId(), subject, publisherId,
				resource, scope, expiresAt));

		Map<String, Object> body = new LinkedHashMap<>();
		body.put("access_token", accessTokenValue);
		body.put("token_type", "Bearer");
		body.put("expires_in", properties.getAccessTokenTtlSeconds());
		body.put("scope", String.join(" ", scope));

		if (issueRefreshToken && properties.isRefreshTokenEnabled()) {
			String refreshTokenValue = OAuthStore.randomToken();
			store.storeRefreshToken(new RefreshToken(refreshTokenValue, client.getClientId(), subject, publisherId,
					resource, scope));
			body.put("refresh_token", refreshTokenValue);
		}

		return jsonResponse(HttpStatus.OK, body);
	}

	private ResponseEntity<Map<String, Object>> error(HttpStatus status, String error, String description) {
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("error", error);
		body.put("error_description", description);
		return jsonResponse(status, body);
	}

	private ResponseEntity<Map<String, Object>> jsonResponse(HttpStatus status, Map<String, Object> body) {
		return ResponseEntity.status(status)
				.header(HttpHeaders.CACHE_CONTROL, "no-store")
				.header(HttpHeaders.PRAGMA, "no-cache")
				.contentType(MediaType.APPLICATION_JSON)
				.body(body);
	}
}
