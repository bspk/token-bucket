package io.bspk.token;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.Arrays;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author jricher
 *
 */
public class Bucket {

	byte[] hash; // calculated hash

	String token; // token value

	List<Bucket> parents; // parent nodes

	String tag; // application-specific tag

	String format; // internal format of the token

	List<BucketSignature> signatures;


	// check if the hash is already calculated, throw an error if it is
	private void checkChange() {
		if (this.hash != null) {
			throw new IllegalAccessError("Once hash is calculated, values cannot be changed.");
		}
	}


	/**
	 * @return the hash
	 */
	public byte[] getHash() {

		if (this.hash != null) {
			return Arrays.copyOf(this.hash, this.hash.length);
		}

		if (this.token == null) {
			throw new IllegalAccessError("Token value is required.");
		}

		Digest h = SHA256Digest.newInstance();

		byte[] out = new byte[32];

		// add bytes of token
		h.update(this.token.getBytes(), 0, this.token.getBytes().length);

		// add parents in order
		if (this.parents != null) {
			this.parents.forEach(p -> {
				h.update(p.getHash(), 0, p.getHash().length);
			});
		}

		// add tag
		if (this.tag != null) {
			h.update(this.tag.getBytes(), 0, this.tag.getBytes().length);
		}

		// add format
		if (this.format != null) {
			h.update(this.format.getBytes(), 0, this.format.getBytes().length);
		}

		h.doFinal(out, 0);

		this.hash = out;

		return this.hash;
	}


	public String getEncodedHash() {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(getHash());
	}



	/**
	 * @return the token
	 */
	public String getToken() {
		return token;
	}


	/**
	 * @param token the token to set
	 * @return
	 */
	public Bucket setToken(String token) {
		checkChange();
		this.token = token;
		return this;
	}


	/**
	 * @return the parents
	 */
	public List<Bucket> getParents() {
		if (this.parents == null) {
			return null;
		} else {
			return Collections.unmodifiableList(this.parents);
		}
	}


	/**
	 * @param parents the parents to set
	 */
	public Bucket addParent(Bucket parent) {
		checkChange();
		if (this.parents == null) {
			this.parents = new ArrayList<>();
		}

		this.parents.add(parent);

		return this;
	}


	/**
	 * @return the tag
	 */
	public String getTag() {
		return tag;
	}


	/**
	 * @param tag the tag to set
	 * @return
	 */
	public Bucket setTag(String tag) {
		checkChange();
		this.tag = tag;
		return this;
	}


	/**
	 * @return the format
	 */
	public String getFormat() {
		return format;
	}


	/**
	 * @param format the format to set
	 */
	public Bucket setFormat(String format) {
		checkChange();
		this.format = format;
		return this;
	}

	public List<BucketSignature> getSignatures() {
		return Collections.unmodifiableList(this.signatures);
	}

	public Bucket sign(PrivateKey key, String alg, String keyId) {
		try {

			Signature signer = Signature.getInstance(alg);
			signer.initSign(key);

			signer.update(getHash());
			BucketSignature sig = new BucketSignature(signer.sign(), keyId);

			if (this.signatures == null) {
				this.signatures = new ArrayList<>();
			}

			this.signatures.add(sig);
			return this;
		} catch (SignatureException | NoSuchAlgorithmException | InvalidKeyException e) {
			throw new IllegalAccessError("Could not sign bucket: " +  e.getMessage());
		}
	}

	public String serialize() {

		StringBuffer sb = new StringBuffer();

		sb.append("\"");
		sb.append(getToken());
		sb.append("\"");

		if (getTag() != null) {
			sb.append("\n   ;tag=");
			sb.append(getTag());
		}

		if (getFormat() != null) {
			sb.append("\n   ;format=");
			sb.append(getFormat());
		}

		if (getParents() != null) {
			sb.append("\n   ;parents=");
			sb.append(getParents().stream()
				.map(Bucket::getEncodedHash)
				.collect(Collectors.joining(",", "(", ")")));
		}

		if (getSignatures() != null) {
			sb.append("\n   ;sig=");
			sb.append(getSignatures().stream()
				.map(BucketSignature::serialize)
				.collect(Collectors.joining(",", "(", ")")));
		}

		return sb.toString();

	}


	/**
	 * @return
	 */
	private boolean hasParams() {
		return getTag() != null || getParents() != null || getFormat() != null;
	}
}
