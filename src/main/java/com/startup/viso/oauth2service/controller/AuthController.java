package com.startup.viso.oauth2service.controller;

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

@RestController
@RequestMapping(value = "/api/v1")
public class AuthController {

    @GetMapping(value = "/viso", produces = "application/json")
    public String viso() {
        return "Congrats! You are granted to access VISO APIs.";
    }

}
