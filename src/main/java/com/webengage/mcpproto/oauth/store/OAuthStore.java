package com.webengage.mcpproto.oauth.store;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

import com.webengage.mcpproto.config.OAuthProperties;
import com.webengage.mcpproto.oauth.model.AccessToken;
import com.webengage.mcpproto.oauth.model.AuthorizationCode;
import com.webengage.mcpproto.oauth.model.PendingAuthorizationRequest;
import com.webengage.mcpproto.oauth.model.RefreshToken;
import com.webengage.mcpproto.oauth.model.RegisteredClient;

import jakarta.annotation.PostConstruct;

/**
 * All prototype state lives in memory - a real deployment would use a database, but nothing
 * here needs to survive a restart, and in-memory keeps the whole OAuth mechanics visible in
 * one place for debugging against real Claude/ChatGPT traffic.
 */
@Component
public class OAuthStore {

	// SHOULD cache CIMD metadata respecting HTTP cache headers per spec; this prototype uses
	// a flat TTL instead for simplicity.
	private static final Duration CIMD_CACHE_TTL = Duration.ofMinutes(5);

	private final OAuthProperties properties;

	private final Map<String, RegisteredClient> preRegisteredClients = new ConcurrentHashMap<>();
	private final Map<String, CachedClient> cimdCache = new ConcurrentHashMap<>();
	private final Map<String, PendingAuthorizationRequest> pendingRequests = new ConcurrentHashMap<>();
	private final Map<String, AuthorizationCode> codes = new ConcurrentHashMap<>();
	private final Map<String, AccessToken> accessTokens = new ConcurrentHashMap<>();
	private final Map<String, RefreshToken> refreshTokens = new ConcurrentHashMap<>();

	public OAuthStore(OAuthProperties properties) {
		this.properties = properties;
	}

	@PostConstruct
	void loadPreRegisteredClients() {
		for (OAuthProperties.ClientConfig cfg : properties.getPreRegisteredClients()) {
			if (cfg.getClientId() == null || cfg.getClientId().isBlank()) {
				continue;
			}
			RegisteredClient client = new RegisteredClient(
					cfg.getClientId(),
					cfg.getClientSecret(),
					List.of(cfg.getRedirectUri()),
					cfg.getName() != null ? cfg.getName() : cfg.getClientId(),
					"client_secret_post");
			preRegisteredClients.put(client.getClientId(), client);
		}
	}

	public RegisteredClient getPreRegisteredClient(String clientId) {
		return preRegisteredClients.get(clientId);
	}

	public RegisteredClient getCachedCimdClient(String url) {
		CachedClient cached = cimdCache.get(url);
		if (cached == null) {
			return null;
		}
		if (Instant.now().isAfter(cached.cachedAt.plus(CIMD_CACHE_TTL))) {
			cimdCache.remove(url);
			return null;
		}
		return cached.client;
	}

	public void cacheCimdClient(String url, RegisteredClient client) {
		cimdCache.put(url, new CachedClient(client, Instant.now()));
	}

	public String storePendingRequest(PendingAuthorizationRequest request) {
		String id = randomToken();
		pendingRequests.put(id, request);
		return id;
	}

	/** One-shot: a pending request is consumed by the consent page exactly once. */
	public PendingAuthorizationRequest takePendingRequest(String id) {
		return id == null ? null : pendingRequests.remove(id);
	}

	public void storeCode(AuthorizationCode code) {
		codes.put(code.getCode(), code);
	}

	public AuthorizationCode getCode(String code) {
		return code == null ? null : codes.get(code);
	}

	public void storeAccessToken(AccessToken token) {
		accessTokens.put(token.getToken(), token);
	}

	public AccessToken getAccessToken(String token) {
		return token == null ? null : accessTokens.get(token);
	}

	public void storeRefreshToken(RefreshToken token) {
		refreshTokens.put(token.getToken(), token);
	}

	public RefreshToken getRefreshToken(String token) {
		return token == null ? null : refreshTokens.get(token);
	}

	public static String randomToken() {
		byte[] bytes = new byte[32];
		new SecureRandom().nextBytes(bytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	private record CachedClient(RegisteredClient client, Instant cachedAt) {
	}
}
