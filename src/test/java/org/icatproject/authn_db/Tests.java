package org.icatproject.authn_db;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class Tests {

	@Test
	public void getDescription() {
		DB_Authenticator authn = new DB_Authenticator();
		assertEquals("{\"keys\":[{\"name\":\"username\"},{\"name\":\"password\",\"hide\":true}]}",
				authn.getDescription());
	}

}