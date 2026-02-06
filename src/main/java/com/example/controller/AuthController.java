package com.example.controller;

import com.example.DAO.UserRepository;
import com.example.bean.User;
import com.example.dto.LoginRequest;
import com.example.dto.SignupRequest;
import com.example.security.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseCookie;

import java.util.List;
import java.util.Map;

@RestController
public class AuthController {

    private final UserRepository repo;
    private final PasswordEncoder encoder;

    public AuthController(UserRepository repo, PasswordEncoder encoder) {
        this.repo = repo;
        this.encoder = encoder;
    }

    @GetMapping("/home")
    public ResponseEntity<?> gethome(){
        return ResponseEntity.ok("welcome to homepage");
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody SignupRequest req) {

        if (repo.findByUsername(req.username()).isPresent()) {
            return ResponseEntity.badRequest().body("User exists");
        }

//        System.out.println("req.username()");

        User user = new User();
        user.setUsername(req.username());
        user.setPasswordHash(encoder.encode(req.password()));

//        System.out.println(user.toString());

        repo.save(user);
        return ResponseEntity.ok("Signup successful");
    }



    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody LoginRequest req,
            HttpServletResponse response
            ) {

        User user = repo.findByUsername(req.username())
                .orElseThrow(() -> new RuntimeException("Invalid credentials"));

        if (!encoder.matches(req.password(), user.getPasswordHash())) {
            return ResponseEntity.status(401).body("Invalid credentials");
        }

        String token = JwtUtil.generateToken(user.getUsername());

        ResponseCookie cookie = ResponseCookie.from("access_token", token)
                .httpOnly(true)
                .secure(false) // true in production (HTTPS)
                .path("/")
                .sameSite("Strict")
                .maxAge(15 * 60) // 15 minutes
                .build();

        response.addHeader("Set-Cookie", cookie.toString());

        return ResponseEntity.ok(
                Map.of("accessToken", token)
        );
    }





}
