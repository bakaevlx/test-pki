package org.my.tes.pki;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import org.apache.commons.codec.binary.Base64;

public class PKIUtil {
	
	
	public static KeyPair readKeyPairFromKeystore(String jksPath, String alias, String pwd) throws Exception {
		
		System.out.println("Load keystore " + jksPath);
		
		try(InputStream in = new FileInputStream(new File(jksPath));){
			
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(in, pwd.toCharArray());

			Certificate cert = ks.getCertificate(alias);

			KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks
					.getEntry(alias, new KeyStore.PasswordProtection(pwd.toCharArray()));
			PrivateKey pk = pkEntry.getPrivateKey();
			
			return new KeyPair(cert.getPublicKey(), pk);
			
		}

	}
	
	public static Certificate readCertificateFromKeystore(String jksPath, String alias, String pwd) throws Exception {	
		
		System.out.println("Load keystore " + jksPath);
		
		try(InputStream in = new FileInputStream(new File(jksPath));){		
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(in, pwd.toCharArray());
			return ks.getCertificate(alias);			
		}

	}

	/**
	 * PEM format, header, footer and base 64 DER encoded certificate in between.
	 */
	public static void writeToPEMCertFile(Certificate cert, String certFilePath)
			throws CertificateEncodingException, IOException {
		try (FileOutputStream os = new FileOutputStream(certFilePath);) {
			os.write("-----BEGIN CERTIFICATE-----\n".getBytes("US-ASCII"));
			os.write(Base64.encodeBase64(cert.getEncoded(), true));
			os.write("-----END CERTIFICATE-----\n".getBytes("US-ASCII"));
		}
	}
	
	public static Certificate readPEMCertFile(String certFilePath) throws CertificateException, FileNotFoundException {
		final CertificateFactory fact = CertificateFactory.getInstance("X.509");
		Certificate cert = fact.generateCertificate(new FileInputStream(new File(certFilePath)));
		return cert;		
	}

}