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

import com.example.DAO.RefreshTokenRepository;
import com.example.bean.RefreshToken;
import com.example.security.RefreshTokenUtil;

import jakarta.servlet.http.Cookie;


import java.util.List;
import java.util.Map;

@RestController
public class AuthController {

    private final UserRepository repo;
    private final PasswordEncoder encoder;
    private final RefreshTokenRepository refreshRepo;
    private static final long ACCESS_EXPIRY_SECONDS = 15 * 60;       // 15 min
    private static final long REFRESH_EXPIRY_SECONDS = 7 * 24 * 60 * 60; // 7 days



    public AuthController(
            UserRepository repo,
            PasswordEncoder encoder,
            RefreshTokenRepository refreshRepo
    ) {
        this.repo = repo;
        this.encoder = encoder;
        this.refreshRepo = refreshRepo;
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

        String username = user.getUsername();

        // 1️⃣ Generate access token (JWT)
        String accessToken = JwtUtil.generateToken(username);

        // 2️⃣ Generate refresh token (random)
        String refreshTokenValue = RefreshTokenUtil.generateToken();

        long expiryEpoch = System.currentTimeMillis() + (REFRESH_EXPIRY_SECONDS * 1000);

        RefreshToken refreshToken = new RefreshToken(
                refreshTokenValue,
                username,
                expiryEpoch
        );

        // 3️⃣ Save refresh token (server-side)
        refreshRepo.save(refreshToken);

        // 4️⃣ Set Access Token cookie
        ResponseCookie accessCookie = ResponseCookie.from("access_token", accessToken)
                .httpOnly(true)
                .secure(false) // true in production
                .path("/")
                .sameSite("Strict")
                .maxAge(ACCESS_EXPIRY_SECONDS)
                .build();

        // 5️⃣ Set Refresh Token cookie
        ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", refreshTokenValue)
                .httpOnly(true)
                .secure(false)
                .path("/")
                .sameSite("Strict")
                .maxAge(REFRESH_EXPIRY_SECONDS)
                .build();

        response.addHeader("Set-Cookie", accessCookie.toString());
        response.addHeader("Set-Cookie", refreshCookie.toString());

        return ResponseEntity.ok("Login successful");


    }





    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest request,
                                     HttpServletResponse response) {

        // 1️⃣ Extract refresh token from cookies
        String refreshTokenValue = null;

        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("refresh_token".equals(cookie.getName())) {
                    refreshTokenValue = cookie.getValue();
                }
            }
        }

        if (refreshTokenValue == null || refreshTokenValue.isBlank()) {
            return ResponseEntity.status(401).body("No refresh token");
        }

        // 2️⃣ Lookup
        RefreshToken existing = refreshRepo.findByToken(refreshTokenValue)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        // 3️⃣ Expiry check
        if (existing.getExpiryEpoch() < System.currentTimeMillis()) {
            refreshRepo.delete(refreshTokenValue);
            return ResponseEntity.status(401).body("Refresh token expired");
        }

        String username = existing.getUsername();

        // 4️⃣ ROTATION: delete old token
        refreshRepo.delete(refreshTokenValue);

        // 5️⃣ Create new refresh token
        String newRefreshValue = RefreshTokenUtil.generateToken();

        long newExpiry = System.currentTimeMillis() + (7L * 24 * 60 * 60 * 1000);

        RefreshToken newRefresh = new RefreshToken(
                newRefreshValue,
                username,
                newExpiry
        );

        refreshRepo.save(newRefresh);

        // 6️⃣ Create new access token
        String newAccessToken = JwtUtil.generateToken(username);

        // 7️⃣ Set cookies

        ResponseCookie accessCookie = ResponseCookie.from("access_token", newAccessToken)
                .httpOnly(true)
                .secure(false)
                .path("/")
                .sameSite("Strict")
                .maxAge(15 * 60)
                .build();

        ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", newRefreshValue)
                .httpOnly(true)
                .secure(false)
                .path("/")
                .sameSite("Strict")
                .maxAge(7 * 24 * 60 * 60)
                .build();

        response.addHeader("Set-Cookie", accessCookie.toString());
        response.addHeader("Set-Cookie", refreshCookie.toString());

        return ResponseEntity.ok("Tokens refreshed");
    }








    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request,
                                    HttpServletResponse response) {


        // 1️⃣ Extract refresh token
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("refresh_token".equals(cookie.getName())) {
                    refreshRepo.delete(cookie.getValue());
                }
            }
        }

        ResponseCookie accessCookie = ResponseCookie.from("access_token", "")
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(0)
                .build();

        ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", "")
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(0)
                .build();

        response.addHeader("Set-Cookie", accessCookie.toString());
        response.addHeader("Set-Cookie", refreshCookie.toString());

        return ResponseEntity.ok("Logged out");
    }















}


// short lived access token
// long lived refresh token



// problems : new refresh token being created on every login, also even
// with refresh token rotation the new token would still go to attacker!


// solution to problem 2 :
// no real user is going to manually play with cookies
// hence absence of cookie -> go to login
// trying to login when cookie already there -> no need to generate refresh token again


// “Logout from this device”
//“Logout from all devices”
//Device management screen (like Google)