package com.auth.demo.authdemo.service;

import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class TokenStorageService {
    Logger logger = LoggerFactory.getLogger(TokenStorageService.class);
    private Map<String, JsonObject> tokenStorage;

    public TokenStorageService() {
        tokenStorage = new HashMap<>();
    }

    public void addToken(JsonObject token) {
        logger.info(String.format("Adding new token %s", token.get("access_token").getAsString()));
        tokenStorage.put(token.get("access_token").getAsString(), token);
    }

    public JsonObject getToken(String accessToken) {
        logger.info(String.format("Getting token by access token: %s", accessToken));
        return tokenStorage.get(accessToken);
    }
}
