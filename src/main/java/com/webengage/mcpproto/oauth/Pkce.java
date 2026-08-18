package com.webengage.mcpproto.oauth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/** RFC 7636 PKCE S256 challenge computation and verification. Only S256 is accepted - OAuth
 * 2.1 requires it "when technically capable", and every real MCP client is. */
public final class Pkce {

	public static final String METHOD_S256 = "S256";

	private Pkce() {
	}

	public static String s256Challenge(String verifier) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.US_ASCII));
			return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
		}
		catch (NoSuchAlgorithmException e) {
			// SHA-256 is guaranteed available on every JDK distribution.
			throw new IllegalStateException(e);
		}
	}

	/** Verifies a code_verifier against a stored challenge. Rejects anything but S256. */
	public static boolean verify(String verifier, String challenge, String method) {
		if (verifier == null || verifier.isBlank() || challenge == null || !METHOD_S256.equals(method)) {
			return false;
		}
		String computed = s256Challenge(verifier);
		return MessageDigest.isEqual(
				computed.getBytes(StandardCharsets.US_ASCII),
				challenge.getBytes(StandardCharsets.US_ASCII));
	}
}
