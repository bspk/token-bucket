package io.bspk.token;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * A container for multiple buckets.
 *
 * @author jricher
 *
 */
public class Crate {

	private Set<Bucket> buckets = new HashSet<>();

	public Crate addBucket(Bucket b) {

		// ensure bucket is finalized before adding
		b.getHash();

		List<Bucket> parents = b.getParents();

		if (parents != null) {
			parents.forEach(p -> {
				if (!buckets.contains(p)) {
					throw new IllegalAccessError("Parent referenced but not found in crate, add parent first.");
				}
			});
		}

		buckets.add(b);

		return this;
	}

	public String serialize() {

		return buckets.stream().map(b -> {
			StringBuilder sb = new StringBuilder();
			sb.append(b.getEncodedHash());
			sb.append("=");
			sb.append(b.serialize());
			return sb.toString();
		})
		.collect(Collectors.joining(",\n"));
	}

}
