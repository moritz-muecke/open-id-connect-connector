package org.mule.modules.singlesignonoidc.automation.functional;

import static org.junit.Assert.*;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mule.modules.singlesignonoidc.SingleSignOnOIDCConnector;
import org.mule.tools.devkit.ctf.junit.AbstractTestCase;

public class ActAsRelyingPartyTestCases extends
		AbstractTestCase<SingleSignOnOIDCConnector> {

	public ActAsRelyingPartyTestCases() {
		super(SingleSignOnOIDCConnector.class);
	}

	@Before
	public void setup() {
		// TODO
	}

	@After
	public void tearDown() {
		// TODO
	}

	@Test
	public void verify() {
		java.lang.Object expected = null;
		org.mule.api.callback.SourceCallback callback = null;
		org.mule.api.MuleMessage muleMessage = null;
		assertEquals(getConnector().actAsRelyingParty(callback, muleMessage),
				expected);
	}

}