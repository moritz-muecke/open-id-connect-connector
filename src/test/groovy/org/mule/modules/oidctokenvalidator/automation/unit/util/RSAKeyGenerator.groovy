package org.mule.modules.oidctokenvalidator.automation.unit.util

import java.security.KeyPair
import java.security.KeyPairGenerator

/**
 * Created by moritz.moeller on 08.03.2016.
 */
class RSAKeyGenerator {
    static KeyPair keyPairGenerator() {
        def keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        keyGen.genKeyPair();
    }
}
