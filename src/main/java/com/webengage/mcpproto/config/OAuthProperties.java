package com.webengage.mcpproto.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "webengage.oauth")
public class OAuthProperties {

	private String issuer;
	private String mcpResource;
	private int accessTokenTtlSeconds = 3600;
	private boolean refreshTokenEnabled = true;
	private List<ClientConfig> preRegisteredClients = new ArrayList<>();

	public String getIssuer() {
		return issuer;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	public String getMcpResource() {
		return mcpResource;
	}

	public void setMcpResource(String mcpResource) {
		this.mcpResource = mcpResource;
	}

	public int getAccessTokenTtlSeconds() {
		return accessTokenTtlSeconds;
	}

	public void setAccessTokenTtlSeconds(int accessTokenTtlSeconds) {
		this.accessTokenTtlSeconds = accessTokenTtlSeconds;
	}

	public boolean isRefreshTokenEnabled() {
		return refreshTokenEnabled;
	}

	public void setRefreshTokenEnabled(boolean refreshTokenEnabled) {
		this.refreshTokenEnabled = refreshTokenEnabled;
	}

	public List<ClientConfig> getPreRegisteredClients() {
		return preRegisteredClients;
	}

	public void setPreRegisteredClients(List<ClientConfig> preRegisteredClients) {
		this.preRegisteredClients = preRegisteredClients;
	}

	public static class ClientConfig {
		private String clientId;
		private String clientSecret;
		private String redirectUri;
		private String name;

		public String getClientId() {
			return clientId;
		}

		public void setClientId(String clientId) {
			this.clientId = clientId;
		}

		public String getClientSecret() {
			return clientSecret;
		}

		public void setClientSecret(String clientSecret) {
			this.clientSecret = clientSecret;
		}

		public String getRedirectUri() {
			return redirectUri;
		}

		public void setRedirectUri(String redirectUri) {
			this.redirectUri = redirectUri;
		}

		public String getName() {
			return name;
		}

		public void setName(String name) {
			this.name = name;
		}
	}
}
