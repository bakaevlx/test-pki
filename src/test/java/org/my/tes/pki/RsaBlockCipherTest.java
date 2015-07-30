package org.my.tes.pki;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.my.tes.pki.PKIUtilTest.*;

import java.security.KeyPair;
import java.util.regex.Pattern;

import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(org.junit.runners.BlockJUnit4ClassRunner.class)
public class RsaBlockCipherTest {


	@Test
	public void testCipher() throws Exception {

		final String s = "The newly announced Republican presidential candidate told CNN's Dana Bash on Tuesday that he will sign up for health care coverage through the Affordable Care Act -- a law he has been on a crusade to kill.\n"
				+ "We'll be getting new health insurance and we'll presumably do it through my job with the Senate, and so we'll be on the federal exchange with millions of others on the federal exchange, Cruz said.";

		final KeyPair kp = PKIUtil.readKeyPairFromKeystore(jksPath, alias, pwd);
		
		String enc = new RsaBlockCipher().encrypt(s, kp.getPublic());
		assertNotNull(enc);	
		
		// test base64
		if(enc.length() == 0 || enc.length() % 4 != 0)
			fail();
		assertTrue(Pattern.matches("[a-zA-Z0-9/\\+]+=*", enc.trim()));
		
		String dec = new RsaBlockCipher().decrypt(enc, kp.getPrivate());
		assertNotNull(dec);
//		System.out.println("decrypt: " + dec);
		assertEquals(s, dec);

	}
}
