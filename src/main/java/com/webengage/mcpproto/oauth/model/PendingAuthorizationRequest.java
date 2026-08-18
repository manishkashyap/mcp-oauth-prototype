package com.webengage.mcpproto.oauth.model;

import java.util.Set;

/**
 * A validated authorization request awaiting the fake login/consent step. Created after
 * {@code /oauth2/authorize} has already confirmed the client, exact redirect_uri, resource,
 * and PKCE method are all valid - by the time this exists, redirectUri is trusted enough to
 * redirect error responses to.
 */
public class PendingAuthorizationRequest {

	private final String clientId;
	private final String clientName;
	private final String redirectUri;
	private final String resource;
	private final Set<String> scope;
	private final String codeChallenge;
	private final String codeChallengeMethod;
	private final String state;

	public PendingAuthorizationRequest(String clientId, String clientName, String redirectUri,
			String resource, Set<String> scope, String codeChallenge, String codeChallengeMethod,
			String state) {
		this.clientId = clientId;
		this.clientName = clientName;
		this.redirectUri = redirectUri;
		this.resource = resource;
		this.scope = Set.copyOf(scope);
		this.codeChallenge = codeChallenge;
		this.codeChallengeMethod = codeChallengeMethod;
		this.state = state;
	}

	public String getClientId() {
		return clientId;
	}

	public String getClientName() {
		return clientName;
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

	public String getState() {
		return state;
	}
}
