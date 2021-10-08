import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSignatureSpi.SHA1;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSignatureSpi.SHA512;
import org.bouncycastle.jcajce.provider.digest.SHA224;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.util.encoders.Hex;

public class Test {
	public static void main(String[] args) throws NoSuchAlgorithmException {
		
		String input = "Hello world !";
	    SHA3.DigestSHA3 digestSHA3 = new SHA3.Digest512();
	    byte[] digest = digestSHA3.digest(input.getBytes());

	    System.out.println("SHA3-512 = " + Hex.toHexString(digest));

	}
}
