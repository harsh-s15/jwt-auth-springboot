package com.example.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class MeController {

    @GetMapping("/me")
    public ResponseEntity<?> me(Authentication auth) {
        if (auth == null || !auth.isAuthenticated()) {
            return ResponseEntity.status(401).body("Not authenticated");
        }

        return ResponseEntity.ok(
                Map.of("username", auth.getName())
        );
    }
}


// on fetching login : first check if me controller returning valid. if yes :
// already logged in, redirect to homepage
// homepage backend controller will still test auth but now react knows that it will work