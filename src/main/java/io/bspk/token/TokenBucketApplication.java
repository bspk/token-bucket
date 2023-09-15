package io.bspk.token;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class TokenBucketApplication {

	public static void main(String[] args) throws Exception {

		Crate c = new Crate();

		Bucket b1 = new Bucket()
			.setToken("8765trfghjuyt5rtghjki987y6tfghj")
			.setFormat("opaque")
			.setTag("api");


		Bucket b2 = new Bucket()
			.setToken("2wsdfghgfr45tyhjkiuytg")
			.setFormat("jwt")
			.setTag("gateway")
			.addParent(b1);


		Bucket b3 = new Bucket()
			.setToken("vcxsawertghju7654rtyuikjhgfr54refghjukjhgtr54redfghj")
			.setTag("magic")
			.addParent(b1)
			.addParent(b2);

		Bucket b4 = new Bucket()
			.setToken("a")
			.setFormat("secure")
			.addParent(b1)
			.addParent(b3);

		Bucket b5 = new Bucket()
			.setToken("876ytghj4nb2ghj23rjnfdu o2i3rj asdflk 23r")
			.setFormat("illgal-probably")
			.setTag("weird")
			.addParent(b2);

        KeyPairGenerator kpgRsa = KeyPairGenerator.getInstance("RSA");
        kpgRsa.initialize(1024);
        KeyPair k1 = kpgRsa.genKeyPair();

        b2.sign(k1.getPrivate(), "SHA1WithRSA", "k1");
        b1.sign(k1.getPrivate(), "SHA1WithRSA", "k1");
        b4.sign(k1.getPrivate(), "SHA1WithRSA", "k1");

        KeyPairGenerator kpgEc = KeyPairGenerator.getInstance("EC");
        kpgEc.initialize(256);
        KeyPair k2 = kpgEc.generateKeyPair();

        b2.sign(k2.getPrivate(), "SHA1withECDSA", "k2");
        b3.sign(k2.getPrivate(), "SHA1withECDSA", "k2");
        b5.sign(k2.getPrivate(), "SHA1withECDSA", "k2");

		c.addBucket(b1)
			.addBucket(b2)
			.addBucket(b3)
			.addBucket(b4)
			.addBucket(b5);

		System.out.println(c.serialize());

	}

}
