package org.my.tes.pki;


import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.PublicKey;
import java.security.Signature;

import org.apache.commons.io.FileUtils;

public class DigitalSignatureVerifier {


	public static boolean verify(byte[] sig, String dataFilePath, PublicKey pubKey) throws Exception {
		
		Signature dsa = Signature
				.getInstance(DigitalSignatureGenerator.DIG_SIG_ALGORITHM);
		dsa.initVerify(pubKey);

		try (BufferedInputStream bufin = new BufferedInputStream(
				new FileInputStream(dataFilePath));) {
			byte[] buffer = new byte[1024];
			int len;
			while (bufin.available() != 0) {
				len = bufin.read(buffer);
				dsa.update(buffer, 0, len);
			}
			;
		}

		boolean ver = dsa.verify(sig);
		System.out.println("Signature verification: " + ver);
		return ver;
	}

	public static boolean verify(File sigFile, String dataFilePath, PublicKey pubKey)
			throws Exception {
		return verify(FileUtils.readFileToByteArray(sigFile), dataFilePath, pubKey);
	}
}
