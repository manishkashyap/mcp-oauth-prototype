package com.webengage.mcpproto.oauth;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.webengage.mcpproto.config.OAuthProperties;

/**
 * Discovery endpoints. Deliberately advertises only the V1 capability set discussed in
 * MCP_OAUTH_IMPLEMENTATION.md: PKCE S256, client_secret_post OR none (the latter is what
 * lets Claude pick CIMD), and CIMD support. No registration_endpoint (no DCR), no
 * revocation_endpoint, no jwks_uri, no authorization_response_iss_parameter_supported -
 * we don't advertise capabilities V1 doesn't actually have.
 */
@RestController
public class MetadataController {

	private static final List<String> SCOPES_SUPPORTED = List.of("campaigns:read", "integrations:read");

	private final OAuthProperties properties;

	public MetadataController(OAuthProperties properties) {
		this.properties = properties;
	}

	@GetMapping(value = "/.well-known/oauth-authorization-server", produces = MediaType.APPLICATION_JSON_VALUE)
	public Map<String, Object> authorizationServerMetadata() {
		Map<String, Object> metadata = new LinkedHashMap<>();
		metadata.put("issuer", properties.getIssuer());
		metadata.put("authorization_endpoint", properties.getIssuer() + "/oauth2/authorize");
		metadata.put("token_endpoint", properties.getIssuer() + "/oauth2/token");
		metadata.put("response_types_supported", List.of("code"));
		metadata.put("grant_types_supported", List.of("authorization_code", "refresh_token"));
		metadata.put("code_challenge_methods_supported", List.of(Pkce.METHOD_S256));
		// "none" here (alongside client_secret_post) is what makes Claude eligible to pick
		// CIMD at all - it authenticates CIMD clients as public clients at the token endpoint.
		metadata.put("token_endpoint_auth_methods_supported", List.of("client_secret_post", "none"));
		metadata.put("client_id_metadata_document_supported", true);
		metadata.put("scopes_supported", SCOPES_SUPPORTED);
		return metadata;
	}

	@GetMapping(value = "/.well-known/oauth-protected-resource/mcp", produces = MediaType.APPLICATION_JSON_VALUE)
	public Map<String, Object> protectedResourceMetadata() {
		Map<String, Object> metadata = new LinkedHashMap<>();
		metadata.put("resource", properties.getMcpResource());
		metadata.put("authorization_servers", List.of(properties.getIssuer()));
		metadata.put("scopes_supported", SCOPES_SUPPORTED);
		metadata.put("bearer_methods_supported", List.of("header"));
		return metadata;
	}
}
