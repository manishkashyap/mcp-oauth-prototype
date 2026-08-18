package com.webengage.mcpproto.oauth;

import java.util.Optional;

import org.springframework.stereotype.Component;

import com.webengage.mcpproto.oauth.cimd.ClientMetadataFetcher;
import com.webengage.mcpproto.oauth.model.RegisteredClient;
import com.webengage.mcpproto.oauth.store.OAuthStore;

/**
 * Resolves a client_id from either path, in priority order: pre-registered (manual entry)
 * first, then CIMD if the value looks like an HTTPS URL. This mirrors the priority Claude's
 * own client-selection logic follows.
 */
@Component
public class ClientResolver {

	private final OAuthStore store;
	private final ClientMetadataFetcher cimdFetcher;

	public ClientResolver(OAuthStore store, ClientMetadataFetcher cimdFetcher) {
		this.store = store;
		this.cimdFetcher = cimdFetcher;
	}

	public Optional<RegisteredClient> resolve(String clientId) {
		if (clientId == null || clientId.isBlank()) {
			return Optional.empty();
		}

		RegisteredClient preRegistered = store.getPreRegisteredClient(clientId);
		if (preRegistered != null) {
			return Optional.of(preRegistered);
		}

		if (clientId.startsWith("https://")) {
			RegisteredClient cached = store.getCachedCimdClient(clientId);
			if (cached != null) {
				return Optional.of(cached);
			}
			return cimdFetcher.fetch(clientId).map(client -> {
				store.cacheCimdClient(clientId, client);
				return client;
			});
		}

		return Optional.empty();
	}
}
