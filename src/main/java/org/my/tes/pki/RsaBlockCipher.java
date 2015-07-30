package org.my.tes.pki;


import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.ArrayUtils;

/**
 * RSA is a block cipher. See eg http://coding.westreicher.org/?p=23.
 * 
 * <p/>
 * For encryption, use 100 byte max long chunks of plaintext and encrypt each
 * chunk to exactly 256 byte long ciphertext. The last chunk can be shorter than
 * 100 byte. Here 256 corresponds to a 2048 key; use 128 for 1024 keys etc.
 * 
 * <p/>
 * For decryption, use 256 bytes long chunks of ciphertext and decrypt each to
 * max 100 byte long plaintext.
 * 
 */
public class RsaBlockCipher {
	static final String CIPHER_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
	static final String ENCODING = "UTF-8";
	// block cipher
	private Cipher cipher;
	private int idx = 0;
	private int bufSize;
	private byte[] output = new byte[0];
	private byte[] input;
	private boolean continueFlag = true;

	public String encrypt(String plaintext, PublicKey pubk) throws Exception {

		input = plaintext.getBytes(ENCODING);

		cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
		cipher.init(Cipher.ENCRYPT_MODE, pubk);
		bufSize = 100;

		doWork();

		return new String(Base64.encodeBase64(output));
	}

	public String decrypt(String ciphertext, PrivateKey pk) throws Exception {

		input = Base64.decodeBase64(ciphertext.getBytes(ENCODING));

		cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
		cipher.init(Cipher.DECRYPT_MODE, pk);
		bufSize = 256;

		doWork();

		return new String(output);
	}

	private void doWork() throws IllegalBlockSizeException, BadPaddingException {
		while (continueFlag) {
			byte[] cipherOut = cipher.doFinal(prepareBuffer());
			output = ArrayUtils.addAll(output, cipherOut);
		}
	}

	// populate buffer, inc idx
	private byte[] prepareBuffer() {
		
		int length = bufSize;
		int nextIdxVal = idx + bufSize;

		if (nextIdxVal >= input.length) {
			continueFlag = false;
			length = input.length - idx;
		}

		byte[] buffer = new byte[length];
		System.arraycopy(input, idx, buffer, 0, length);
		
		System.out.println("idx=" + idx + " length=" + length);
		
		idx = nextIdxVal;
		
		return buffer;
	}

}
