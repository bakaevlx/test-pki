package org.my.tes.pki;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.my.tes.pki.PKIUtilTest.*;

import java.security.cert.Certificate;

import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(org.junit.runners.BlockJUnit4ClassRunner.class)
public class DigitalSignatureTest {
	
	@Test
	public void testDigSig() throws Exception {
		
		Certificate cert;
		
		final String testFilePath = PKIUtilTest.BASE_PATH + "bathsheba.jpg";
		final String testFilePath_2 = PKIUtilTest.BASE_PATH + "bathsheba_2.jpg";
		
		byte[] sig =  DigitalSignatureGenerator.signFile(testFilePath, jksPath, alias, pwd);
		assertNotNull(sig);
		assertEquals(256, sig.length);
			
		cert = PKIUtil.readPEMCertFile(BASE_PATH + "alex-test.cert");
		
		boolean ver = DigitalSignatureVerifier.verify(sig, testFilePath, cert.getPublicKey());
		assertTrue(ver);
		
		// non-repudiation
		ver = DigitalSignatureVerifier.verify(sig, testFilePath_2, cert.getPublicKey());
		assertFalse(ver);
		
		// verify who signed it
		cert = PKIUtil.readPEMCertFile(BASE_PATH + "tomcat_signed.cert");		
		ver = DigitalSignatureVerifier.verify(sig, testFilePath, cert.getPublicKey());
		assertFalse(ver);	
	}
}
