package org.mule.modules.oidctokenvalidator.automation.unit.util;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public abstract class RSAKeyGenerator {
	public static KeyPair keyPairGenerator() throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	    keyGen.initialize(1024);
	    return keyGen.genKeyPair();
	}
}
