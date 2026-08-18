package com.webengage.mcpproto.oauth.model;

import java.time.Instant;
import java.util.Set;

/** An opaque MCP access token - no JWT/JWKS in this prototype, matching the V1 decision. */
public class AccessToken {

	private final String token;
	private final String clientId;
	private final String subject;
	private final String publisherId;
	private final String resource;
	private final Set<String> scope;
	private final Instant expiresAt;

	public AccessToken(String token, String clientId, String subject, String publisherId,
			String resource, Set<String> scope, Instant expiresAt) {
		this.token = token;
		this.clientId = clientId;
		this.subject = subject;
		this.publisherId = publisherId;
		this.resource = resource;
		this.scope = Set.copyOf(scope);
		this.expiresAt = expiresAt;
	}

	public boolean isExpired() {
		return Instant.now().isAfter(expiresAt);
	}

	public String getToken() {
		return token;
	}

	public String getClientId() {
		return clientId;
	}

	public String getSubject() {
		return subject;
	}

	public String getPublisherId() {
		return publisherId;
	}

	public String getResource() {
		return resource;
	}

	public Set<String> getScope() {
		return scope;
	}

	public Instant getExpiresAt() {
		return expiresAt;
	}
}
