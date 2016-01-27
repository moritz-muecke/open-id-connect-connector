package org.mule.modules.singlesignonoidc.automation.unit;

import org.junit.Before;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mule.modules.singlesignonoidc.client.SignedTokenVerifier;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest(SignedTokenVerifier.class)
public class SignedTokenVerifierTest extends Mockito{

	@Before
	public void init() {
		PowerMockito.mockStatic(SignedTokenVerifier.class);
	}
}
