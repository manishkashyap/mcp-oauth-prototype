package com.webengage.mcpproto.oauth.model;

import java.util.Set;

/**
 * A non-rotating refresh token - deliberately simple for this prototype (no rotation, no
 * reuse-detection/token-family tracking). Real WebEngage V1 decided to skip refresh tokens
 * entirely and rely on a longer access-token TTL instead; this prototype exists partly to
 * observe how Claude behaves with vs. without one, since Claude's docs say it refreshes
 * proactively 5 minutes before expiry and reactively on a 401.
 */
public class RefreshToken {

	private final String token;
	private final String clientId;
	private final String subject;
	private final String publisherId;
	private final String resource;
	private final Set<String> scope;

	public RefreshToken(String token, String clientId, String subject, String publisherId,
			String resource, Set<String> scope) {
		this.token = token;
		this.clientId = clientId;
		this.subject = subject;
		this.publisherId = publisherId;
		this.resource = resource;
		this.scope = Set.copyOf(scope);
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
}
