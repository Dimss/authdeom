package com.auth.demo.authdemo.service;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import com.google.gson.JsonParser;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;


@Service
public class AuthService {
    Logger logger = LoggerFactory.getLogger(AuthService.class);
    private OkHttpClient client;
    private JsonParser parser;
    private JsonObject wellKnownConfigs;
    @Autowired
    private TokenStorageService tokenStorageService;
    @Value("${app.ssoBaseUrl}")
    private String ssoBaseUrl;
    @Value("${app.realmName}")
    private String realmName;
    @Value("${app.clientId}")
    private String clientId;
    @Value("${app.clientSecret}")
    private String clientSecret;
    @Value("${app.authCallback}")
    private String callbackUrl;
    @Value("${app.kid}")
    private String kid;


    public AuthService() {
        this.client = new OkHttpClient();
        this.parser = new JsonParser();
    }

    @PostConstruct
    private void initWellKnownConfigs() {
        try {
            // Load well known configs
            logger.info("Fetching token");
            Request request = new Request.Builder().url(this.getOpenIdConfigUrl()).build();
            Response response = client.newCall(request).execute();
            JsonObject jo = parser.parse(response.body().string()).getAsJsonObject();
            this.wellKnownConfigs = jo;
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String getOpenIdConfigUrl() {
        String configUrl = String.format("%s/auth/realms/%s/.well-known/openid-configuration", this.ssoBaseUrl, this.getRealmName());
        logger.info(String.format("Well Known URL: %s", configUrl));
        return configUrl;
    }

    public String getRealmName() {
        return realmName;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getAuthorizationEndpoint() {
        return this.wellKnownConfigs.get("authorization_endpoint").getAsString();
    }

    public String getTokenEndpoint() {
        return this.wellKnownConfigs.get("token_endpoint").getAsString();
    }

    public String getUserInfoEndpoint() {
        return this.wellKnownConfigs.get("userinfo_endpoint").getAsString();
    }

    public String getEndSessionEndpoint() {
        return this.wellKnownConfigs.get("end_session_endpoint").getAsString();
    }

    public String getJwksUri() {
        return this.wellKnownConfigs.get("jwks_uri").getAsString();
    }

    public JsonObject getJwks() {
        HttpUrl.Builder httpUrlBuilder = HttpUrl.parse(this.getJwksUri()).newBuilder();
        Request request = new Request.Builder().url(httpUrlBuilder.build()).build();
        Response response = null;
        try {
            response = client.newCall(request).execute();
            JsonArray ja = parser.parse(response.body().string()).getAsJsonObject().get("keys").getAsJsonArray();
            // at index 0, I don't care
            return ja.get(0).getAsJsonObject();
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException();
        }
    }

    public String getAuthUrl() {
        HttpUrl.Builder httpUrlBuilder = HttpUrl.parse(this.getAuthorizationEndpoint()).newBuilder();
        httpUrlBuilder.addQueryParameter("client_id", this.getClientId());
        httpUrlBuilder.addQueryParameter("client_secret", this.getClientSecret());
        httpUrlBuilder.addQueryParameter("scope", "openid");
        httpUrlBuilder.addQueryParameter("response_type", "code");
        httpUrlBuilder.addQueryParameter("redirect_uri", this.callbackUrl);
        return httpUrlBuilder.build().toString();
    }

    public String getAccessToken(String code) {
        // Once authenticated by SSO, gonna fetch the
        // authentication object by providing authorization code
        RequestBody body = new FormBody.Builder()
                .add("code", code)
                .add("grant_type", "authorization_code")
                .add("redirect_uri", this.callbackUrl)
                .add("client_id", this.clientId)
                .add("client_secret", this.clientSecret)
                .build();
        // Build request
        Request request = new Request.Builder().url(this.getTokenEndpoint()).post(body).build();
        Response response = null;
        try {
            // Exec HTTP GET
            response = client.newCall(request).execute();
            // Parse response into JsonObject
            JsonObject authRes = parser.parse(response.body().string()).getAsJsonObject();
            // Store token to in memory for further logout action
            tokenStorageService.addToken(authRes);
            // Return access token
            return authRes.get("access_token").getAsString();
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException();
        }
    }

    public JsonObject validateAndDecodeToken(String accessToken) {
        try {
            // Validate and decode token by loading public key int JWK
            JwkProvider provider = new UrlJwkProvider(new URL(this.getJwksUri()));
            // Find the keys by kid
            Jwk jwk = provider.get(this.kid);
            // Load keys
            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
            // Create verifier object
            JWTVerifier verifier = JWT.require(algorithm).build();
            // Decode and verify token
            DecodedJWT jwt = verifier.verify(accessToken);
            // Extract all data from the token payload and send it to client
            Map<String, Claim> claims = jwt.getClaims();
            JsonObject jo = new JsonObject();
            jo.addProperty("algorithm", jwt.getAlgorithm());
            jo.addProperty("type", jwt.getType());
            jo.addProperty("issuer", jwt.getIssuer());
            jo.addProperty("subject", jwt.getSubject());
            jo.addProperty("expiresAt", jwt.getExpiresAt().toString());
            jo.addProperty("issuedAt", jwt.getIssuedAt().toString());
            claims.forEach((k, v) -> {
                // WTF?!
                try {
                    Map<String, Object> o = v.asMap();
                    jo.addProperty(k, o.toString());
                } catch (Exception e) {
                    try {
                        jo.addProperty(k, v.asDate().toString());
                    } catch (Exception e1) {
                        try {
                            jo.addProperty(k, v.asBoolean().toString());
                        } catch (Exception ex) {
                            jo.addProperty(k, v.asString());
                        }
                    }
                }
            });
            return jo;
        } catch (JwkException e) {
            e.printStackTrace();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        throw new RuntimeException();
    }

    public JsonObject getUserInfo(String accessToken) {
        // Get user info by access token
        HttpUrl.Builder httpUrlBuilder = HttpUrl.parse(this.getUserInfoEndpoint()).newBuilder();
        Request request = new Request.Builder()
                .url(httpUrlBuilder.build())
                .header("Authorization", String.format("Bearer %s", accessToken))
                .build();
        Response response = null;
        try {
            response = client.newCall(request).execute();
            JsonObject jo = parser.parse(response.body().string()).getAsJsonObject();
            return jo;
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException();
        }
    }

    public String logout(String accessToken) {
        // Build logout url, get refresh_token from
        // in memory HashMap by accessToken key
        RequestBody body = new FormBody.Builder()
                .add("client_id", this.getClientId())
                .add("client_secret", this.getClientSecret())
                .add("refresh_token", tokenStorageService.getToken(accessToken).get("refresh_token").getAsString())
                .build();
        Request request = new Request.Builder().url(this.getEndSessionEndpoint()).post(body).build();
        try {
            client.newCall(request).execute();
            return "ok";
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException();
        }
    }
}
