package com.auth.demo.authdemo.controller;


import com.auth.demo.authdemo.service.RealmConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

@RestController
@RequestMapping("/v1")
public class AuthController {

    @Autowired
    RealmConfig realmConfig;

    @GetMapping("/auth")
    public RedirectView auth() {
        return new RedirectView(realmConfig.getAuthUrl());
    }

    @GetMapping("/oauth2callback")
    public RedirectView oauth2callback(@RequestParam("code") String code) {
        String accessToken = realmConfig.getAccessToken(code);
        return new RedirectView(String.format("/index.html?access_token=%s", accessToken));
    }

    @GetMapping("/validate")
    public ResponseEntity validateToken(@RequestParam("access_token") String accessToken) {
        return ResponseEntity.ok().body(realmConfig.validateAndDecodeToken(accessToken).toString());
    }

    @GetMapping("/user")
    public ResponseEntity getUserDetails(@RequestParam("access_token") String accessToken) {
        return ResponseEntity.ok().body(realmConfig.getUserInfo(accessToken).toString());
    }
}
