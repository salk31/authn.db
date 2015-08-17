package org.icatproject.authn_db;

import static org.junit.Assert.assertEquals;

import org.icatproject.authentication.Authenticator;
import org.junit.Test;

public class TestGetDescription {
	@Test
	public void test() throws Exception {
		Authenticator a = new DB_Authenticator();
		assertEquals("{\"keys\":[{\"name\":\"username\"},{\"name\":\"password\",\"hide\":true}]}", a.getDescription());
	}
}