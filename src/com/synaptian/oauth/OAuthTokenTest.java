package com.synaptian.oauth;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Scanner;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.params.ConnManagerParams;
import org.apache.http.entity.mime.MultipartEntity;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;

import java.util.logging.Logger;
import java.util.regex.MatchResult;

public class OAuthTokenTest {
	private static Logger log =
			  Logger.getLogger(OAuthTokenTest.class.getName());

    public static final String PARAM_USERNAME = "user[email]";
    public static final String PARAM_PASSWORD = "user[password]";
    public static final String PARAM_REMEMBER = "user[remember_me]";
    public static final String PARAM_CSRF = "authenticity_token";
    public static final String PARAM_AUTH_TOKEN = "authtoken";

    public static final String BASE_URL = "http://smoke-track.herokuapp.com";
    public static final String AUTH_URI = BASE_URL + "/users/sign_in";

	public static void main(String[] args) {
		String token = authenticate("wholcomb@syaptian.com", "heavyapple");
		log.info("Token: " + token);
	}
	
    public static String authenticate(String username, String password) {
        HttpResponse resp;

		String csrfToken = null;

        try {
            URL url = new URL(AUTH_URI);
	        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
	        connection.setRequestMethod("GET");
			
	        InputStream istream = connection.getInputStream();
	        if (istream != null) {
	        	Scanner scanner = new Scanner(istream);
	        	scanner.findWithinHorizon("<meta content=\"([^\"]+)\" name=\"csrf-token\" */>", istream.available());
	        	MatchResult match = scanner.match();
	        	if(match != null) {
	        		csrfToken = match.group(1);
	        		log.info("CSRF: " + csrfToken);
	        	} else {
	            	log.severe("CSRF token not found");
	                return null;
	        	}
	        }
		} catch (ClientProtocolException e) {
        	log.severe("ClientProtocolException when getting csrf token");
            return null;
		} catch (IOException e) {
        	log.severe("IOException when getting csrf token");
            return null;
		}
        
		try {
	        URL url = new URL(AUTH_URI + "?" + PARAM_CSRF + "=" + URLEncoder.encode(csrfToken, "UTF-8"));
	        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
	        connection.setDoOutput(true);
	        connection.setRequestMethod("POST");

	        MultipartEntityBuilder entityBuilder = MultipartEntityBuilder.create();
	        entityBuilder.addTextBody("utf8", "\u2713");
	        entityBuilder.addTextBody(PARAM_USERNAME, username);
	        entityBuilder.addTextBody(PARAM_PASSWORD, password);
	        entityBuilder.addTextBody(PARAM_REMEMBER, "0");
	        entityBuilder.addTextBody(PARAM_CSRF, csrfToken);
	        entityBuilder.addTextBody("commit", "Sign in");

	        HttpEntity entity = entityBuilder.build();

	        log.info("Type: " + entity.getContentType().getValue());
	        
	        connection.setRequestProperty("Content-Type", entity.getContentType().getValue());
	        OutputStream out = connection.getOutputStream();
	        try {
	            entity.writeTo(out);
	        } finally {
	            out.close();
	        }
        	log.info("Response Code: " + connection.getResponseCode());
	    } catch (MalformedURLException e) {
        	log.severe("MalformedURLException when getting oauth token");
            return null;
		} catch (UnsupportedEncodingException e) {
        	log.severe("UnsupportedEncodingException when getting oauth token");
            return null;
		} catch (IOException e) {
        	log.severe("IOException when getting oauth token");
            return null;
		}
		return null;
    }
}
