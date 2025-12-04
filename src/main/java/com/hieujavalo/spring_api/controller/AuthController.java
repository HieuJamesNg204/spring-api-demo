package com.hieujavalo.spring_api.controller;

import com.hieujavalo.spring_api.dto.*;
import com.hieujavalo.spring_api.entity.User;
import com.hieujavalo.spring_api.service.AuthService;
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
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(response);
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