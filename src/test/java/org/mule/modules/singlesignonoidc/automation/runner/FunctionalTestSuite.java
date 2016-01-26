package org.mule.modules.singlesignonoidc.automation.runner;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;
import org.mule.modules.singlesignonoidc.automation.functional.ActAsRelyingPartyTestCases;
import org.mule.modules.singlesignonoidc.automation.functional.LocalTokenValidationTestCases;
import org.mule.modules.singlesignonoidc.automation.functional.OnlineTokenValidationTestCases;
import org.mule.modules.singlesignonoidc.SingleSignOnOIDCConnector;
import org.mule.tools.devkit.ctf.mockup.ConnectorTestContext;

@RunWith(Suite.class)
@SuiteClasses({ ActAsRelyingPartyTestCases.class,
		LocalTokenValidationTestCases.class,
		OnlineTokenValidationTestCases.class })
public class FunctionalTestSuite {

	@BeforeClass
	public static void initialiseSuite() {
		ConnectorTestContext.initialize(SingleSignOnOIDCConnector.class);
	}

	@AfterClass
	public static void shutdownSuite() {
		ConnectorTestContext.shutDown();
	}

}