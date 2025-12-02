package com.hieujavalo.spring_api.controller;

import com.hieujavalo.spring_api.dto.*;
import com.hieujavalo.spring_api.entity.User;
import com.hieujavalo.spring_api.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
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
        AuthResponse response = authService.register(request, false);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/admin/register")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<AuthResponse> registerAdmin(@Valid @RequestBody RegisterRequest request) {
        AuthResponse response = authService.register(request, true);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/confirm-code")
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
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/profile")
    public ResponseEntity<ProfileResponse> getProfile(@AuthenticationPrincipal User user) {
        ProfileResponse response = new ProfileResponse(user.getUsername(), user.getEmail(), user.getRole());
        return ResponseEntity.ok(response);
    }
}