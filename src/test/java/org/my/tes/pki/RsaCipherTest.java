package org.my.tes.pki;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.my.tes.pki.PKIUtilTest.*;

import java.security.KeyPair;

import javax.crypto.Cipher;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.BlockJUnit4ClassRunner;

@RunWith(BlockJUnit4ClassRunner.class)
public class RsaCipherTest {
	
		
	@Test
	public void testRSACipher() throws Exception {
		
		String plainText = "Simple test string";
		
		final KeyPair kp = PKIUtil.readKeyPairFromKeystore(jksPath, alias, pwd);

		Cipher cipher = Cipher.getInstance(RsaBlockCipher.CIPHER_TRANSFORMATION);
		cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());;

		byte[] cipherTxt = cipher.doFinal(plainText.getBytes());
		assertNotNull(cipherTxt);

		cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
		String str = new String(cipher.doFinal(cipherTxt));

		assertNotNull(str);
		assertTrue(cipherTxt.length > 0);
		assertEquals(0, cipherTxt.length % 256);
		assertEquals(str, plainText);

	}

}
