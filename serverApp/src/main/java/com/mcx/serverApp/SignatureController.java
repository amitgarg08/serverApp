package com.mcx.serverApp;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

import javax.annotation.PostConstruct;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.itextpdf.signatures.PrivateKeySignature;

@RestController
public class SignatureController {
	Logger logger = LoggerFactory.getLogger(SignatureController.class);

	private PrivateKey pk;
	@PostMapping("/sign")
	public HSResult signedHash(@RequestBody byte[] hash) throws Exception {
		logger.info("Hash value retrieved by back-end service is :: {}", Arrays.toString(hash));
		PrivateKeySignature signature = new PrivateKeySignature(pk, "SHA256", null);
		byte[] extSignature = signature.sign(hash);
		logger.info("Signed Hash value returned by back-end service is :: {}", Arrays.toString(extSignature));
		return new HSResult(extSignature);
	}

	@PostConstruct
	public void initSign() throws IOException, GeneralSecurityException {
		String configName = "src/main/resources/pkcs11.cfg";
		Provider providerPKCS11 = Security.getProvider("SunPKCS11");
		providerPKCS11 = providerPKCS11.configure(configName);
		Security.addProvider(providerPKCS11);

		BouncyCastleProvider providerBC = new BouncyCastleProvider();
		Security.addProvider(providerBC);

		String pin = "123456789";
		KeyStore keyStore = KeyStore.getInstance("PKCS11");
		keyStore.load(null, pin.toCharArray());

		String alias = keyStore.aliases().nextElement();
		pk = (PrivateKey) keyStore.getKey(alias, pin.toCharArray());

	}

}