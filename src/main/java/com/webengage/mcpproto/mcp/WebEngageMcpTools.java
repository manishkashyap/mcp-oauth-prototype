package com.webengage.mcpproto.mcp;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Component;

import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;

/**
 * Two fake tools mirroring the two real scopes from MCP_OAUTH_IMPLEMENTATION.md's Initial
 * Scope Mapping, so the OAuth scope-gating story can be exercised end-to-end even though the
 * data is fabricated. The tool-name -> required-scope mapping lives in
 * {@link com.webengage.mcpproto.mcp.McpBearerAuthFilter#REQUIRED_SCOPE} rather than an
 * annotation here, since peeking into the JSON-RPC body to enforce it happens at the filter,
 * not via Spring AI's own tool-invocation pipeline.
 */
@Component
public class WebEngageMcpTools {

	@McpTool(name = "search_campaigns_with_stats",
			description = "Search WebEngage campaigns and return stats (prototype - returns fixed fake data)")
	public Map<String, Object> searchCampaignsWithStats(
			@McpToolParam(description = "Free-text search query", required = false) String query) {
		return Map.of(
				"query", query == null ? "" : query,
				"campaigns", List.of(
						Map.of("id", "camp_1001", "name", "Welcome Series", "sent", 12450, "openRate", 0.42),
						Map.of("id", "camp_1002", "name", "Cart Abandonment", "sent", 8790, "openRate", 0.31)));
	}

	@McpTool(name = "get_channel_integration_status",
			description = "Get integration status for a channel (prototype - returns fixed fake data)")
	public Map<String, Object> getChannelIntegrationStatus(
			@McpToolParam(description = "Channel name, e.g. email, sms, push", required = true) String channel) {
		return Map.of(
				"channel", channel,
				"status", "connected",
				"lastSyncedAt", Instant.now().toString());
	}
}
