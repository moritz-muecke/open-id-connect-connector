package org.mule.modules.openidconnect.automation.unit.util

import java.security.KeyPair
import java.security.KeyPairGenerator

/**
 * Util to generate random RSA key pairs for tests
 *
 * @author Moritz Möller, AOE GmbH
 *
 */
class RSAKeyGenerator {
    static KeyPair keyPairGenerator() {
        def keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        keyGen.genKeyPair();
    }
}
