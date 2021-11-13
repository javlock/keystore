package com.github.javlock.keystore.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class KeyUtils {
	private static final String RSA_ECB_OAEPWITHSHA_512ANDMGF1PADDING = "RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING";
	private static final String KEYSTORETYPE = "PKCS12";
	private static final String ENTRYNAME = "owlstead";
	private static final String RSA = "RSA";
	private static final int KEYLEN = 2048;
	private static final String SIGNATUREALGORITHM = "SHA256WithRSA";
	static BouncyCastleProvider provider;

	static {
		provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		Security.addProvider(provider);
	}

	public static byte[] decrypt(byte[] dataE, RSAPrivateKey privKey) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		// Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING
		// Padding
		Cipher cipher = Cipher.getInstance(RSA_ECB_OAEPWITHSHA_512ANDMGF1PADDING);

		// Initialize Cipher for DECRYPT_MODE
		cipher.init(Cipher.DECRYPT_MODE, privKey);

		// Perform Decryption
		return cipher.doFinal(dataE);
	}

	public static byte[] encrypt(String data, RSAPublicKey pubKey) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		// Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING
		// Padding
		Cipher cipher = Cipher.getInstance(RSA_ECB_OAEPWITHSHA_512ANDMGF1PADDING);

		// Initialize Cipher for ENCRYPT_MODE
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);

		// Perform Encryption
		return cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
	}

	public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA);
		generator.initialize(KEYLEN, new SecureRandom());
		return generator.generateKeyPair();
	}

	public static KeyPair restoreFromString(byte[] input, char[] password) throws NoSuchAlgorithmException,
			UnrecoverableEntryException, KeyStoreException, CertificateException, IOException {
		KeyStore pkcs12KeyStore = KeyStore.getInstance(KEYSTORETYPE);

		InputStream is = new ByteArrayInputStream(input);
		pkcs12KeyStore.load(is, password);

		KeyStore.ProtectionParameter param = new KeyStore.PasswordProtection(password);
		Entry entry = pkcs12KeyStore.getEntry(ENTRYNAME, param);
		if (!(entry instanceof PrivateKeyEntry)) {
			throw new KeyStoreException("That's not a private key!");
		}
		PrivateKeyEntry privKeyEntry = (PrivateKeyEntry) entry;
		PublicKey publicKey = privKeyEntry.getCertificate().getPublicKey();
		PrivateKey privateKey = privKeyEntry.getPrivateKey();
		return new KeyPair(publicKey, privateKey);
	}

	public static Certificate selfSign(KeyPair keyPair, String subjectDN)
			throws OperatorCreationException, CertificateException {

		long now = System.currentTimeMillis();
		Date startDate = new Date(now);

		X500Name dnName = new X500Name(subjectDN);

		// Using the current timestamp as the certificate serial number
		BigInteger certSerialNumber = new BigInteger(Long.toString(now));

		Calendar calendar = Calendar.getInstance();
		calendar.setTime(startDate);
		// 1 Yr validity
		calendar.add(Calendar.YEAR, 1);

		Date endDate = calendar.getTime();

		// Use appropriate signature algorithm based on your keyPair algorithm.

		SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

		X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(dnName, certSerialNumber, startDate,
				endDate, dnName, subjectPublicKeyInfo);

		ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATUREALGORITHM).setProvider(provider)
				.build(keyPair.getPrivate());

		X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);

		return new JcaX509CertificateConverter().getCertificate(certificateHolder);
	}

	public static byte[] storeToString(KeyPair generatedKeyPair, ProtectionParameter param, char[] password)
			throws IOException, OperatorCreationException, CertificateException, KeyStoreException,
			NoSuchAlgorithmException {
		Certificate selfSignedCertificate = selfSign(generatedKeyPair, "CN=owlstead");

		KeyStore pkcs12KeyStore = KeyStore.getInstance(KEYSTORETYPE);
		pkcs12KeyStore.load(null, null);

		KeyStore.Entry entry = new KeyStore.PrivateKeyEntry(generatedKeyPair.getPrivate(),
				new Certificate[] { selfSignedCertificate });
		pkcs12KeyStore.setEntry(ENTRYNAME, entry, param);

		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			pkcs12KeyStore.store(baos, password);
			return baos.toByteArray();
		}
	}

	private KeyUtils() {
	}

}
