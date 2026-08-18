package com.webengage.mcpproto.oauth.cimd;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webengage.mcpproto.oauth.model.RegisteredClient;

/**
 * Fetches and validates an OAuth Client ID Metadata Document (draft-ietf-oauth-client-id-
 * metadata-document-00) from a client-supplied HTTPS URL, per the MCP client-registration spec.
 *
 * <p>This is the SSRF-shaped operation the MCP security-considerations page flags: we're
 * making an outbound request to a URL someone else handed us. The mitigations here follow the
 * IETF draft's own (fairly general) guidance - avoid private/loopback addresses, cap response
 * size, use HTTPS only - plus reasonable defaults (fixed timeout, no redirect following,
 * content-type check) that the spec leaves to implementers.
 *
 * <p><b>Known gap, called out rather than hidden:</b> the private/loopback IP check below
 * resolves DNS once via {@link InetAddress#getAllByName}, then lets {@link HttpClient} resolve
 * and connect separately - a DNS-rebinding attacker could in principle return a safe IP for our
 * check and a private one at actual connect time. Closing that gap needs a resolver that pins
 * the checked IP for the actual connection (e.g. a custom SSLSocketFactory/Resolver), which
 * this prototype skips as out of scope for validating protocol behavior against real clients.
 * Don't carry this class's SSRF handling into production without addressing that.
 */
@Component
public class ClientMetadataFetcher {

	private static final int MAX_RESPONSE_BYTES = 5 * 1024; // spec's own DoS guidance
	private static final Duration TIMEOUT = Duration.ofSeconds(5);

	private final HttpClient httpClient = HttpClient.newBuilder()
			.connectTimeout(TIMEOUT)
			.followRedirects(HttpClient.Redirect.NEVER)
			.build();

	private final ObjectMapper mapper = new ObjectMapper();

	/**
	 * @param clientIdUrl the client_id value from the authorization/token request - must be
	 *                     the exact HTTPS URL to fetch and must appear verbatim as "client_id"
	 *                     in the fetched document.
	 */
	public Optional<RegisteredClient> fetch(String clientIdUrl) {
		URI uri;
		try {
			uri = new URI(clientIdUrl);
		}
		catch (URISyntaxException e) {
			return Optional.empty();
		}

		if (!"https".equalsIgnoreCase(uri.getScheme())) {
			return Optional.empty();
		}
		// Spec: "the client_id URL MUST use the https scheme and contain a path component".
		if (uri.getPath() == null || uri.getPath().isBlank() || "/".equals(uri.getPath())) {
			return Optional.empty();
		}
		if (!isHostSafe(uri.getHost())) {
			return Optional.empty();
		}

		HttpRequest request;
		try {
			request = HttpRequest.newBuilder(uri)
					.timeout(TIMEOUT)
					.header("Accept", "application/json")
					.GET()
					.build();
		}
		catch (IllegalArgumentException e) {
			return Optional.empty();
		}

		byte[] body;
		String contentType;
		try {
			HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
			if (response.statusCode() != 200) {
				return Optional.empty();
			}
			body = response.body();
			if (body.length > MAX_RESPONSE_BYTES) {
				return Optional.empty();
			}
			contentType = response.headers().firstValue("Content-Type").orElse("");
		}
		catch (IOException e) {
			return Optional.empty();
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return Optional.empty();
		}

		if (!contentType.toLowerCase(Locale.ROOT).contains("json")) {
			return Optional.empty();
		}

		return parse(clientIdUrl, body);
	}

	private Optional<RegisteredClient> parse(String clientIdUrl, byte[] body) {
		JsonNode node;
		try {
			node = mapper.readTree(body);
		}
		catch (IOException e) {
			return Optional.empty();
		}
		if (node == null || !node.isObject()) {
			return Optional.empty();
		}

		// Spec: server MUST validate that the fetched document's client_id matches the URL
		// exactly - this is what stops a document at one URL from claiming to be another.
		String docClientId = node.path("client_id").asText(null);
		if (docClientId == null || !docClientId.equals(clientIdUrl)) {
			return Optional.empty();
		}

		String clientName = node.path("client_name").asText(null);
		if (clientName == null || clientName.isBlank()) {
			return Optional.empty();
		}

		List<String> redirectUris = new ArrayList<>();
		JsonNode redirectUrisNode = node.path("redirect_uris");
		if (redirectUrisNode.isArray()) {
			redirectUrisNode.forEach(n -> {
				if (n.isTextual()) {
					redirectUris.add(n.asText());
				}
			});
		}
		if (redirectUris.isEmpty()) {
			return Optional.empty();
		}

		// CIMD clients never present a shared secret - the example document in the spec
		// itself sets "none", and that's the only value that makes sense here.
		String authMethod = node.path("token_endpoint_auth_method").asText("none");

		return Optional.of(new RegisteredClient(clientIdUrl, null, redirectUris, clientName, authMethod));
	}

	private boolean isHostSafe(String host) {
		if (host == null || host.isBlank()) {
			return false;
		}
		try {
			InetAddress[] addresses = InetAddress.getAllByName(host);
			if (addresses.length == 0) {
				return false;
			}
			for (InetAddress addr : addresses) {
				if (addr.isLoopbackAddress() || addr.isAnyLocalAddress() || addr.isLinkLocalAddress()
						|| addr.isSiteLocalAddress() || addr.isMulticastAddress()) {
					return false;
				}
			}
			return true;
		}
		catch (UnknownHostException e) {
			return false;
		}
	}
}
