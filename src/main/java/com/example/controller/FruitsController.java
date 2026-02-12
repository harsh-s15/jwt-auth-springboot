package com.example.controller;

import com.example.DAO.UserRepository;
import com.example.bean.User;
//import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.springframework.security.core.Authentication;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/fruits")
public class FruitsController {
    private final UserRepository repo;

    public FruitsController(UserRepository repo) {
        this.repo = repo;
    }

    @GetMapping
    public List<String> getFruits(Authentication auth) {
        User user = repo.findByUsername(auth.getName()).orElseThrow();
        return user.getFruits();
    }

    @PostMapping
    public ResponseEntity<?> addFruit(
            Authentication auth,
            @RequestBody String fruit
    ) {
        User user = repo.findByUsername(auth.getName()).orElseThrow();
        user.getFruits().add(fruit);
        repo.save(user);
        return ResponseEntity.ok("Added");
    }
    
}
