# 10. Store Tokens in HTTP-Only
Storing tokens (especially JWT access/refresh tokens) in localStorage is risky because JavaScript can access it — meaning XSS attacks can steal your tokens.
This section will explore how to store tokens in HTTP-Only, which is the best alternative.
## Step 1: Update JWT utilisation
Update `JwtUtil` with access tokens (short lifetime - 5 minutes) and refresh ones (long lifetime - a week).
**util/JwtUtil.java**
```java
package com.hieujavalo.spring_api.util;

import com.hieujavalo.spring_api.entity.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
@Slf4j
public class JwtUtil {
    @Value("${jwt.secret}") // From application.properties
    private String secret;

    @Value("${jwt.access.expiration:300000}") // in ms - 300000 ms = 5 minutes
    private long accessExpiration;

    @Value("${jwt.refresh.expiration:604800000}") // a week
    private long refreshExpiration;

    private SecretKey getSigningKey() {
        byte[] decodedKey = secret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(decodedKey);
    }

    public String generateAccessToken(User user) {
        return Jwts.builder()
                .subject(user.getUsername())
                .claim("role", user.getRole().name())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + accessExpiration))
                .signWith(getSigningKey())
                .compact();
    }

    public String generateRefreshToken(User user) {
        return Jwts.builder()
                .subject(user.getUsername())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + refreshExpiration))
                .signWith(getSigningKey())
                .compact();
    }

    public String extractUsername(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getSubject();
        } catch (Exception e) {
            log.error("Error extracting username from token", e);
            return null;
        }
    }

    public String extractRole(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .get("role", String.class);
        } catch (Exception e) {
            log.error("Error extracting role from token", e);
            return null;
        }
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            log.error("Invalid token", e);
            return false;
        }
    }
}
```
## Step 2: Update authentication service
Update authentication to handle the logics of refresh tokens.
**service/AuthService.java**
```java
package com.hieujavalo.spring_api.service;

import com.hieujavalo.spring_api.dto.*;
import com.hieujavalo.spring_api.entity.User;
import com.hieujavalo.spring_api.enums.Role;
import com.hieujavalo.spring_api.exception.ResourceNotFoundException;
import com.hieujavalo.spring_api.exception.UnauthorizedException;
import com.hieujavalo.spring_api.repository.UserRepository;
import com.hieujavalo.spring_api.util.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Random;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final EmailService emailService;
    private static final long CODE_EXPIRATION_MS = 10 * 60 * 1000; // 10 minutes

    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("Username already exists");
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email already exists");
        }

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.CUSTOMER);
        user.setEnabled(false); // disable until confirmed

        // Generate 6-digit numeric verification code
        String code = String.format("%06d", new Random().nextInt(1000000));
        user.setVerificationCode(code);
        user.setVerificationCodeGeneratedAt(System.currentTimeMillis());

        userRepository.save(user);

        // Send email
        String emailBody = "Hello " + user.getUsername() + ",<br><br>" +
                "Thank you for registering with our system. " +
                "To complete your registration, please use the verification code below:<br><br>" +
                "<b style='font-size:18px;'>" + user.getVerificationCode() + "</b><br><br>" +
                "This code will expire in 10 minutes for security purposes.<br><br>" +
                "If you did not request this, please ignore this email.<br><br>" +
                "Best regards,<br>" +
                "Hieu JavaLo";
        emailService.sendEmail(
                user.getEmail(),
                "Confirm your registration",
                emailBody
        );

        return new AuthResponse(null, request.getUsername(), user.getRole(),
                "Registration successful! Check your email to confirm.");
    }

    public AuthResponse login(LoginRequest request, HttpServletResponse response) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new UnauthorizedException("Invalid credentials"));

        if (!user.isEnabled()) {
            throw new IllegalArgumentException("Email not confirmed yet");
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new UnauthorizedException("Invalid credentials");
        }

        String accessToken = jwtUtil.generateAccessToken(user);
        String refreshToken = jwtUtil.generateRefreshToken(user);

        ResponseCookie cookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/api/v1/auth/refresh")
                .maxAge(7 * 24 * 3600)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return new AuthResponse(accessToken, user.getUsername(), user.getRole(), "Login successful!");
    }

    public void logout(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/api/v1/auth/refresh")
                .maxAge(0)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    public AuthResponse refreshAccessToken(String refreshToken) {
        if (refreshToken == null) {
            throw new UnauthorizedException("Refresh token missing");
        }

        if (!jwtUtil.validateToken(refreshToken)) {
            throw new UnauthorizedException("Invalid refresh token");
        }

        String username = jwtUtil.extractUsername(refreshToken);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        String newAccessToken = jwtUtil.generateAccessToken(user);
        return new AuthResponse(newAccessToken, username, user.getRole(), "Token refreshed");
    }

    public void confirmEmail(String code) {
        User user = userRepository.findByVerificationCode(code)
                .orElseThrow(() -> new IllegalArgumentException("Invalid confirmation code"));

        long now = System.currentTimeMillis();
        if (user.getVerificationCodeGeneratedAt() == null ||
                now - user.getVerificationCodeGeneratedAt() > CODE_EXPIRATION_MS) {
            throw new IllegalArgumentException("Verification code expired");
        }

        user.setEnabled(true);
        user.setVerificationCode(null);
        user.setVerificationCodeGeneratedAt(null);
        userRepository.save(user);
    }

    public void resendVerificationCode(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Email not registered"));

        if (user.isEnabled()) {
            throw new IllegalArgumentException("Email already confirmed");
        }

        // Generate a new 6-digit code
        String code = String.format("%06d", new Random().nextInt(1000000));
        user.setVerificationCode(code);
        user.setVerificationCodeGeneratedAt(System.currentTimeMillis());

        userRepository.save(user);

        // Send email
        String emailBody =  "Hello " + user.getUsername() + ",<br><br>" +
                "We have received your request to send a new verification code. Your new code is:<br><br>" +
                "<b style='font-size:18px;'>" + user.getVerificationCode() + "</b><br><br>" +
                "This code will expire in 10 minutes for security purposes.<br><br>" +
                "If you did not request this, please ignore this email.<br><br>" +
                "Best regards,<br>" +
                "Hieu JavaLo";
        emailService.sendEmail(
                user.getEmail(),
                "Resend verification code",
                emailBody
        );
    }

    public void sendResetPasswordCode(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Email not registered"));

        String code = String.format("%06d", new Random().nextInt(1000000));
        user.setResetPasswordCode(code);
        user.setResetPasswordCodeGeneratedAt(System.currentTimeMillis());
        userRepository.save(user);

        String message = "<p>Hello " + user.getUsername() + ",</p>"
                + "<p>We have received your request to reset your password. Please use the verification code below:</p>"
                + "<p style='font-size:18px; font-weight:bold;'>" + code + "</p>"
                + "<p>This code will expire in 10 minutes for security purposes.</p>"
                + "<p>If you did not request this, you can safely ignore the email.</p>"
                + "<p>Best regards,<br/>Your Support Team</p>";
        emailService.sendEmail(user.getEmail(), "Password Reset Request", message);
    }

    public void resetPassword(String code, String newPassword) {
        User user = userRepository.findByResetPasswordCode(code)
                .orElseThrow(() -> new IllegalArgumentException("Invalid reset code"));

        long now = System.currentTimeMillis();
        if (user.getResetPasswordCodeGeneratedAt() == null ||
                now - user.getResetPasswordCodeGeneratedAt() > CODE_EXPIRATION_MS) {
            throw new IllegalArgumentException("Reset code expired");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setResetPasswordCode(null);
        user.setResetPasswordCodeGeneratedAt(null);
        userRepository.save(user);
    }

    public void changeEmail(User user, EmailRequest request) {
        String email = request.getEmail();

        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("Email already taken");
        }

        String code = String.format("%06d", new Random().nextInt(1000000));

        user.setPendingEmail(email);
        user.setEmailChangeCode(code);
        user.setEmailChangeCodeGeneratedAt(System.currentTimeMillis());

        userRepository.save(user);

        String emailBody =  "Hello " + user.getUsername() + ",<br><br>" +
                "We have received your new email address. To secure your new email, please use the verification " +
                "code below:<br><br>" +
                "<b style='font-size:18px;'>" + user.getEmailChangeCode() + "</b><br><br>" +
                "This code will expire in 10 minutes for security purposes.<br><br>" +
                "If you did not request this, please ignore this email.<br><br>" +
                "Best regards,<br>" +
                "Hieu JavaLo";
        emailService.sendEmail(
                email,
                "Confirm your new email address",
                emailBody
        );
    }

    public void confirmEmailChange(User user, CodeRequest request) {
        long now = System.currentTimeMillis();
        if (user.getEmailChangeCodeGeneratedAt() == null ||
                now - user.getEmailChangeCodeGeneratedAt() > CODE_EXPIRATION_MS) {
            throw new IllegalArgumentException("Email change code expired");
        }

        if (!request.getCode().equals(user.getEmailChangeCode())) {
            throw new IllegalArgumentException("Invalid email change code");
        }

        user.setEmail(user.getPendingEmail());

        user.setPendingEmail(null);
        user.setEmailChangeCode(null);
        user.setEmailChangeCodeGeneratedAt(null);

        userRepository.save(user);
    }

    public void resendEmailChangeCode(User user) {
        String code = String.format("%06d", new Random().nextInt(1000000));

        user.setEmailChangeCode(code);
        user.setEmailChangeCodeGeneratedAt(System.currentTimeMillis());
        userRepository.save(user);

        String emailBody =  "Hello " + user.getUsername() + ",<br><br>" +
                "We have received your new email address. To secure your new email, please use the verification " +
                "code below:<br><br>" +
                "<b style='font-size:18px;'>" + user.getEmailChangeCode() + "</b><br><br>" +
                "This code will expire in 10 minutes for security purposes.<br><br>" +
                "If you did not request this, please ignore this email.<br><br>" +
                "Best regards,<br>" +
                "Hieu JavaLo";
        emailService.sendEmail(
                user.getPendingEmail(),
                "Confirm your new email address",
                emailBody
        );
    }

    public void changePassword(User user, ChangePasswordRequest request) {
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Invalid password");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }
}
```
## Step 3: Update authentication controller
Add new endpoints to the authentication controller in order to refresh tokens and log out.
**controller/AuthController.java**
```java
package com.hieujavalo.spring_api.controller;

import com.hieujavalo.spring_api.dto.*;
import com.hieujavalo.spring_api.entity.User;
import com.hieujavalo.spring_api.service.AuthService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@Slf4j
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        AuthResponse response = authService.register(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/confirm-code")
    public ResponseEntity<String> confirmEmailCode(@Valid @RequestBody CodeRequest request) {
        authService.confirmEmail(request.getCode());
        return ResponseEntity.ok("Email confirmed! You can now log in.");
    }

    @PostMapping("/resend-code")
    public ResponseEntity<String> resendCode(@Valid @RequestBody EmailRequest request) {
        authService.resendVerificationCode(request.getEmail());
        return ResponseEntity.ok("Verification code resent! Check your email.");
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request, HttpServletResponse response) {
        AuthResponse res = authService.login(request, response);
        return ResponseEntity.ok(res);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(
            @CookieValue(value = "refreshToken", required = false) String refreshToken
    ) {
        AuthResponse response = authService.refreshAccessToken(refreshToken);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletResponse response) {
        authService.logout(response);
        return ResponseEntity.ok("Logged out!");
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestBody EmailRequest request) {
        authService.sendResetPasswordCode(request.getEmail());
        return ResponseEntity.ok("Reset code sent to your email!");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request.getCode(), request.getPassword());
        return ResponseEntity.ok("Password reset successful!");
    }

    @PostMapping("/resend-reset-code")
    public ResponseEntity<String> resendPasswordResetCode(@RequestBody EmailRequest request) {
        authService.sendResetPasswordCode(request.getEmail());
        return ResponseEntity.ok("Reset code resent! Check your email.");
    }

    @GetMapping("/profile")
    public ResponseEntity<ProfileResponse> getProfile(@AuthenticationPrincipal User user) {
        ProfileResponse response = new ProfileResponse(user.getUsername(), user.getEmail(), user.getRole());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/change-email/request")
    public ResponseEntity<String> requestEmailChange(@Valid @RequestBody EmailRequest request,
                                                     @AuthenticationPrincipal User user) {
        authService.changeEmail(user, request);
        return ResponseEntity.ok("Verification code sent to your new email!");
    }

    @PostMapping("/change-email/confirm")
    public ResponseEntity<String> confirmEmailChange(@Valid @RequestBody CodeRequest request,
                                                     @AuthenticationPrincipal User user) {
        authService.confirmEmailChange(user, request);
        return ResponseEntity.ok("Email updated successfully");
    }

    @PostMapping("/change-email/resend-code")
    public ResponseEntity<String> resendEmailChangeCode(@AuthenticationPrincipal User user) {
        authService.resendEmailChangeCode(user);
        return ResponseEntity.ok("Verification code sent to your new email!");
    }

    @PostMapping("/change-password")
    public ResponseEntity<String> changePassword(@Valid @RequestBody ChangePasswordRequest request,
                                                 @AuthenticationPrincipal User user) {
        authService.changePassword(user, request);
        return ResponseEntity.ok("Password changed successfully");
    }
}
```
## Step 4: Run application
Now run your application and test