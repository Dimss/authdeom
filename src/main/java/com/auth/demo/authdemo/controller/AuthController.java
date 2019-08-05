package com.auth.demo.authdemo.controller;


import com.auth.demo.authdemo.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

@RestController
@RequestMapping("/v1")
public class AuthController {

    @Autowired
    AuthService authService;

    @GetMapping("/auth")
    public RedirectView auth() {
        return new RedirectView(authService.getAuthUrl());
    }

    @GetMapping("/oauth2callback")
    public RedirectView oauth2callback(@RequestParam("code") String code) {
        String accessToken = authService.getAccessToken(code);
        return new RedirectView(String.format("/index.html?access_token=%s", accessToken));
    }

    @GetMapping("/validate")
    public ResponseEntity validateToken(@RequestParam("access_token") String accessToken) {
        return ResponseEntity.ok().body(authService.validateAndDecodeToken(accessToken).toString());
    }

    @GetMapping("/user")
    public ResponseEntity getUserDetails(@RequestParam("access_token") String accessToken) {
        return ResponseEntity.ok().body(authService.getUserInfo(accessToken).toString());
    }

    @RequestMapping(value = "/logout", method = RequestMethod.DELETE)
    public ResponseEntity logout(@RequestParam("access_token") String accessToken) {
        return ResponseEntity.ok().body(authService.logout(accessToken));
    }
}

