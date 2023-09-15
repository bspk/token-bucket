package io.bspk.token;

import java.util.Base64;

/**
 * @author jricher
 *
 */
public class BucketSignature {

	private byte[] sig;
	private String keyId;

	public BucketSignature(byte[] sig, String keyId) {
		if (sig == null || keyId == null || keyId.isBlank()) {
			throw new IllegalArgumentException("Signature and keyId must not be null or blank.");
		}
		this.sig = sig;
		this.keyId = keyId;
	}

	public String serialize() {
		String encodedSig = Base64.getUrlEncoder().withoutPadding().encodeToString(this.sig);

		return keyId + "=" + encodedSig;

	}

}
