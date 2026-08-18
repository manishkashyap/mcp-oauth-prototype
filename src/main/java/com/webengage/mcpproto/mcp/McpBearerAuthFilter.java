package com.webengage.mcpproto.mcp;

import java.io.IOException;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webengage.mcpproto.oauth.model.AccessToken;
import com.webengage.mcpproto.oauth.store.OAuthStore;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Sits in front of {@code /mcp}, playing the resource-server role: 401 with a
 * WWW-Authenticate/resource_metadata challenge on a missing/invalid/expired/wrong-audience
 * token, 403 insufficient_scope when a valid token doesn't cover the tool being called.
 *
 * The per-tool scope check parses the JSON-RPC body looking for {@code tools/call} +
 * {@code params.name}. If the body isn't the shape we expect (e.g. a batch request, or a
 * non-tool-call method), this fails OPEN on the scope check specifically - deliberately, since
 * this is a test harness for validating connectivity with real clients, and a scope-check bug
 * masking a genuine connection problem would be a worse outcome than under-enforcing scope in
 * a throwaway prototype. The audience/expiry/token-presence check above it does NOT fail open.
 */
@Component
public class McpBearerAuthFilter extends OncePerRequestFilter {

	static final Map<String, String> REQUIRED_SCOPE = Map.of(
			"search_campaigns_with_stats", "campaigns:read",
			"get_channel_integration_status", "integrations:read");

	private final OAuthStore store;
	private final String mcpResource;
	private final String protectedResourceMetadataUrl;
	private final ObjectMapper mapper = new ObjectMapper();

	public McpBearerAuthFilter(OAuthStore store,
			@Value("${webengage.oauth.mcp-resource}") String mcpResource,
			@Value("${webengage.oauth.issuer}") String issuer) {
		this.store = store;
		this.mcpResource = mcpResource;
		this.protectedResourceMetadataUrl = issuer + "/.well-known/oauth-protected-resource/mcp";
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		return !"/mcp".equals(request.getRequestURI());
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {

		String token = extractBearerToken(request.getHeader(HttpHeaders.AUTHORIZATION));
		if (token == null) {
			unauthorized(response);
			return;
		}

		AccessToken accessToken = store.getAccessToken(token);
		if (accessToken == null || accessToken.isExpired() || !mcpResource.equals(accessToken.getResource())) {
			unauthorized(response);
			return;
		}

		CachedBodyHttpServletRequest cachedRequest = new CachedBodyHttpServletRequest(request);
		String requiredScope = requiredScopeForRequest(cachedRequest);
		if (requiredScope != null && !accessToken.getScope().contains(requiredScope)) {
			insufficientScope(response, requiredScope);
			return;
		}

		request.setAttribute("mcp.subject", accessToken.getSubject());
		request.setAttribute("mcp.publisherId", accessToken.getPublisherId());
		chain.doFilter(cachedRequest, response);
	}

	private String requiredScopeForRequest(CachedBodyHttpServletRequest request) {
		if (!"POST".equalsIgnoreCase(request.getMethod())) {
			return null;
		}
		byte[] body = request.getCachedBody();
		if (body.length == 0) {
			return null;
		}
		try {
			JsonNode node = mapper.readTree(body);
			if (!node.isObject() || !"tools/call".equals(node.path("method").asText(null))) {
				return null;
			}
			String toolName = node.path("params").path("name").asText(null);
			return toolName == null ? null : REQUIRED_SCOPE.get(toolName);
		}
		catch (IOException e) {
			return null;
		}
	}

	private String extractBearerToken(String header) {
		if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7)) {
			return null;
		}
		return header.substring(7).trim();
	}

	private void unauthorized(HttpServletResponse response) throws IOException {
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setHeader(HttpHeaders.WWW_AUTHENTICATE,
				"Bearer resource_metadata=\"" + protectedResourceMetadataUrl + "\"");
		writeJsonError(response, "invalid_token");
	}

	private void insufficientScope(HttpServletResponse response, String scope) throws IOException {
		response.setStatus(HttpServletResponse.SC_FORBIDDEN);
		response.setHeader(HttpHeaders.WWW_AUTHENTICATE,
				"Bearer error=\"insufficient_scope\", scope=\"" + scope + "\", resource_metadata=\""
						+ protectedResourceMetadataUrl + "\"");
		writeJsonError(response, "insufficient_scope");
	}

	private void writeJsonError(HttpServletResponse response, String error) throws IOException {
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.getWriter().write("{\"error\":\"" + error + "\"}");
	}
}
