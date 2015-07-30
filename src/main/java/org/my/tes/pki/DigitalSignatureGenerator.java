package org.my.tes.pki;


import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.security.PrivateKey;
import java.security.Signature;

/**
 * Uses the JDK Security API to generate a digital signature for binary data. 
 * The private key is supposed to be extracted from a keystore.
 *
 */
public class DigitalSignatureGenerator {
	// SHA1withRSA or SHA256withRSA?
	static final String DIG_SIG_ALGORITHM = "SHA256withRSA";


	public static byte[] signFile(String inputFilePath, String jksPath, String alias, String pwd) throws Exception {
		
		Signature dsa = Signature.getInstance(DIG_SIG_ALGORITHM);
		PrivateKey pk = PKIUtil.readKeyPairFromKeystore(jksPath, alias, pwd).getPrivate();
		dsa.initSign(pk);
		
		try (BufferedInputStream bufin = new BufferedInputStream(
				new FileInputStream(inputFilePath))) {
			byte[] buffer = new byte[1024];
			int len;
			while ((len = bufin.read(buffer)) >= 0) {
				dsa.update(buffer, 0, len);
			};
		}
		
		byte[] sig = dsa.sign();		
		return sig;
	}

}
