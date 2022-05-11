package org.icatproject.integration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import jakarta.json.Json;
import jakarta.json.stream.JsonGenerator;
import jakarta.json.stream.JsonParser;
import jakarta.json.stream.JsonParser.Event;
import jakarta.json.stream.JsonParsingException;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.ParseException;
import org.apache.http.StatusLine;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.junit.BeforeClass;
import org.junit.Test;

public class TestRS {

	private static URI server;
	private static String basePath = "/authn.db";

	@BeforeClass
	public static void beforeClass() throws URISyntaxException {
		server = new URI(System.getProperty("serverUrl"));
	}

	@Test
	public void getDescription() throws Exception {
		URI uri = new URIBuilder(server).setPath(basePath + "/" + "description").build();
		System.out.println(uri);
		try (CloseableHttpClient httpclient = HttpClients.createDefault()) {
			HttpGet httpGet = new HttpGet(uri);
			try (CloseableHttpResponse response = httpclient.execute(httpGet)) {
				String responseString = getString(response);
				assertEquals("{\"keys\":[{\"name\":\"username\"},{\"name\":\"password\",\"hide\":true}]}",
						responseString);

			}
		}
	}

	@Test
	public void authenticate() throws URISyntaxException, IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try (JsonGenerator gen = Json.createGenerator(baos)) {
			gen.writeStartObject();
			gen.writeStartArray("credentials");
			gen.writeStartObject().write("username", "root").writeEnd();
			gen.writeStartObject().write("password", "password").writeEnd();
			gen.writeEnd();
			gen.write("ip", "127.0.0.1");
			gen.writeEnd().close();
		}

		URI uri = new URIBuilder(server).setPath(basePath + "/" + "authenticate").build();

		List<NameValuePair> formparams = new ArrayList<>();
		formparams.add(new BasicNameValuePair("json", baos.toString()));
		try (CloseableHttpClient httpclient = HttpClients.createDefault()) {
			HttpPost httpPost = new HttpPost(uri);
			httpPost.setEntity(new UrlEncodedFormEntity(formparams));
			try (CloseableHttpResponse response = httpclient.execute(httpPost)) {
				String responseString = getString(response);
				assertEquals("{\"username\":\"root\",\"mechanism\":\"db\"}", responseString);
			}
		}
	}

	@Test
	public void failedAuthenticate() throws URISyntaxException, IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try (JsonGenerator gen = Json.createGenerator(baos)) {
			gen.writeStartObject();
			gen.writeStartArray("credentials");
			gen.writeStartObject().write("username", "root").writeEnd();
			gen.writeStartObject().write("password", "passwor").writeEnd();
			gen.writeEnd();
			gen.write("ip", "127.0.0.1");
			gen.writeEnd().close();
		}

		URI uri = new URIBuilder(server).setPath(basePath + "/" + "authenticate").build();

		List<NameValuePair> formparams = new ArrayList<>();
		formparams.add(new BasicNameValuePair("json", baos.toString()));
		try (CloseableHttpClient httpclient = HttpClients.createDefault()) {
			HttpPost httpPost = new HttpPost(uri);
			httpPost.setEntity(new UrlEncodedFormEntity(formparams));
			try (CloseableHttpResponse response = httpclient.execute(httpPost)) {
				getString(response);
				fail();
			} catch (RuntimeException e) {
				assertEquals("The username and password do not match", e.getMessage());
			}
		}
	}

	private String getString(CloseableHttpResponse response) throws IOException {
		checkStatus(response);
		HttpEntity entity = response.getEntity();
		if (entity == null) {
			throw new RuntimeException("No http entity returned in response");
		}
		return EntityUtils.toString(entity);
	}

	private void checkStatus(HttpResponse response) throws ParseException, IOException {
		StatusLine status = response.getStatusLine();
		if (status == null) {
			throw new RuntimeException("Status line returned is empty");
		}
		int rc = status.getStatusCode();
		if (rc / 100 != 2) {
			HttpEntity entity = response.getEntity();
			String error;
			if (entity == null) {
				throw new RuntimeException("No explanation provided");
			} else {
				error = EntityUtils.toString(entity);
			}
			try (JsonParser parser = Json.createParser(new ByteArrayInputStream(error.getBytes()))) {
				String code = null;
				String message = null;
				String key = "";
				while (parser.hasNext()) {
					JsonParser.Event event = parser.next();
					if (event == Event.KEY_NAME) {
						key = parser.getString();
					} else if (event == Event.VALUE_STRING) {
						if (key.equals("code")) {
							code = parser.getString();
						} else if (key.equals("message")) {
							message = parser.getString();
						}
					}
				}

				if (code == null || message == null) {
					throw new RuntimeException(error);
				}
				throw new RuntimeException(message);
			} catch (JsonParsingException e) {
				throw new RuntimeException(error);
			}
		}

	}

}