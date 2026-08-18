package com.webengage.mcpproto.oauth.model;

import java.time.Instant;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A single-use authorization code, bound to the client, redirect URI, resource, scope,
 * PKCE challenge, and the fake "user"/publisher the consent screen recorded.
 *
 * Single-use is enforced by {@link #tryConsume()}, a compare-and-set on an AtomicBoolean -
 * this is what makes concurrent/parallel redemption of the same code fail closed rather than
 * racing on a plain boolean field.
 */
public class AuthorizationCode {

	private final String code;
	private final String clientId;
	private final String redirectUri;
	private final String resource;
	private final Set<String> scope;
	private final String codeChallenge;
	private final String codeChallengeMethod;
	private final String subject;
	private final String publisherId;
	private final Instant expiresAt;
	private final AtomicBoolean consumed = new AtomicBoolean(false);

	public AuthorizationCode(String code, String clientId, String redirectUri, String resource,
			Set<String> scope, String codeChallenge, String codeChallengeMethod,
			String subject, String publisherId, Instant expiresAt) {
		this.code = code;
		this.clientId = clientId;
		this.redirectUri = redirectUri;
		this.resource = resource;
		this.scope = Set.copyOf(scope);
		this.codeChallenge = codeChallenge;
		this.codeChallengeMethod = codeChallengeMethod;
		this.subject = subject;
		this.publisherId = publisherId;
		this.expiresAt = expiresAt;
	}

	public boolean tryConsume() {
		return consumed.compareAndSet(false, true);
	}

	public boolean isExpired() {
		return Instant.now().isAfter(expiresAt);
	}

	public String getCode() {
		return code;
	}

	public String getClientId() {
		return clientId;
	}

	public String getRedirectUri() {
		return redirectUri;
	}

	public String getResource() {
		return resource;
	}

	public Set<String> getScope() {
		return scope;
	}

	public String getCodeChallenge() {
		return codeChallenge;
	}

	public String getCodeChallengeMethod() {
		return codeChallengeMethod;
	}

	public String getSubject() {
		return subject;
	}

	public String getPublisherId() {
		return publisherId;
	}
}
