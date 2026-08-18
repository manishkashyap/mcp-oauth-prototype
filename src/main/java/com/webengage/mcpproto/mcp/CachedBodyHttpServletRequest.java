package com.webengage.mcpproto.mcp;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

/**
 * Buffers the request body eagerly so the auth filter can peek at it (to read the JSON-RPC
 * {@code tools/call} method/params for scope enforcement) while still handing Spring AI's MCP
 * transport a normally-readable body afterwards. Safe here because MCP Streamable HTTP
 * client->server messages are single small JSON-RPC payloads, not long-lived request streams.
 */
class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

	private final byte[] cachedBody;

	CachedBodyHttpServletRequest(HttpServletRequest request) throws IOException {
		super(request);
		this.cachedBody = request.getInputStream().readAllBytes();
	}

	byte[] getCachedBody() {
		return cachedBody;
	}

	@Override
	public ServletInputStream getInputStream() {
		return new CachedBodyServletInputStream(cachedBody);
	}

	@Override
	public BufferedReader getReader() {
		return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
	}

	private static final class CachedBodyServletInputStream extends ServletInputStream {

		private final ByteArrayInputStream buffer;

		CachedBodyServletInputStream(byte[] body) {
			this.buffer = new ByteArrayInputStream(body);
		}

		@Override
		public boolean isFinished() {
			return buffer.available() == 0;
		}

		@Override
		public boolean isReady() {
			return true;
		}

		@Override
		public void setReadListener(ReadListener listener) {
			// No async read needed for this prototype's small, fully-buffered bodies.
		}

		@Override
		public int read() {
			return buffer.read();
		}
	}
}
