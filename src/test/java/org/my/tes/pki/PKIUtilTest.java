package org.my.tes.pki;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;

import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(org.junit.runners.BlockJUnit4ClassRunner.class)
public class PKIUtilTest {
	static final String BASE_PATH = "./src/test/resources/";
	static final String jksPath = BASE_PATH + "alex-test.jks";
	static final String alias = "test";
	static final String pwd = "welcome1";

	
	@Test
	public void testReadKeyPairFromKeystore() throws Exception {

		KeyPair kp = PKIUtil.readKeyPairFromKeystore(jksPath, alias, pwd);
		
		PublicKey pub = kp.getPublic();
		assertNotNull(pub);
		assertEquals("RSA", pub.getAlgorithm());
		assertEquals("X.509", pub.getFormat());
		
		PrivateKey pk = kp.getPrivate();
		assertNotNull(pk);
		assertEquals("RSA", pk.getAlgorithm());
		assertEquals("PKCS#8", pk.getFormat());
		assertEquals(2048, ((RSAPrivateKey) pk).getModulus().bitLength());
	}

	/**
	 * Certificate authenticity can be checked by getting the
	 * <strong>certificate fingerprints</strong> via the keytool -printcert
	 * command:
	 * 
	 * <p/>
	 * keytool -printcert -file alex-test.cert
	 */
	@Test
	public void testPEMCertFiles() throws Exception {
		
		final String newCertFilePath = BASE_PATH + "alex-test.cert";
		
		Certificate cert = PKIUtil.readCertificateFromKeystore(jksPath, alias, pwd);

		PKIUtil.writeToPEMCertFile(cert, newCertFilePath);

		Certificate cert2 = PKIUtil.readPEMCertFile(newCertFilePath);
		assertNotNull(cert2);
		assertEquals("X.509", cert2.getType());
		// Verifies that this certificate was signed using the private key that
		// corresponds to the specified public key.
		cert2.verify(cert.getPublicKey());
	}

}
