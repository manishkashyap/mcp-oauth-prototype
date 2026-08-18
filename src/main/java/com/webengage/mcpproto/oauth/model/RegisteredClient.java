package com.webengage.mcpproto.oauth.model;

import java.util.List;

/**
 * A client the authorization server will accept - either one of the pre-registered
 * (manual client_id/secret) entries from config, or one resolved live from a CIMD document.
 * CIMD-resolved clients always have a null clientSecret and "none" as their auth method,
 * since there was never a shared-secret exchange for them.
 */
public class RegisteredClient {

	private final String clientId;
	private final String clientSecret;
	private final List<String> redirectUris;
	private final String clientName;
	private final String tokenEndpointAuthMethod;

	public RegisteredClient(String clientId, String clientSecret, List<String> redirectUris,
			String clientName, String tokenEndpointAuthMethod) {
		this.clientId = clientId;
		this.clientSecret = clientSecret;
		this.redirectUris = List.copyOf(redirectUris);
		this.clientName = clientName;
		this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
	}

	public String getClientId() {
		return clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public List<String> getRedirectUris() {
		return redirectUris;
	}

	public String getClientName() {
		return clientName;
	}

	public String getTokenEndpointAuthMethod() {
		return tokenEndpointAuthMethod;
	}

	public boolean isConfidential() {
		return "client_secret_post".equals(tokenEndpointAuthMethod);
	}

	public boolean redirectUriAllowed(String uri) {
		return uri != null && redirectUris.contains(uri);
	}
}
