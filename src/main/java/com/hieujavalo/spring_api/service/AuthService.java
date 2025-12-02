package com.hieujavalo.spring_api.service;

import com.hieujavalo.spring_api.dto.AuthResponse;
import com.hieujavalo.spring_api.dto.LoginRequest;
import com.hieujavalo.spring_api.dto.RegisterRequest;
import com.hieujavalo.spring_api.entity.User;
import com.hieujavalo.spring_api.enums.Role;
import com.hieujavalo.spring_api.repository.UserRepository;
import com.hieujavalo.spring_api.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

    public AuthResponse register(RegisterRequest request, boolean isAdmin) {
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
        user.setEnabled(false); // disable until confirmed

        // Generate 6-digit numeric verification code
        int code = new Random().nextInt(900000) + 100000;
        user.setVerificationCode(String.valueOf(code));

        if (isAdmin && request.getRole() != null) {
            user.setRole(request.getRole());
        } else {
            user.setRole(Role.CUSTOMER);
        }

        userRepository.save(user);

        // Send email
        String emailBody = "Thank you for registering into the system! " +
                "To continue, please use this code to verify your registration: <b>" +
                user.getVerificationCode() + "</b>.<br>Please take note that this code will expire in 10 minutes.";
        emailService.sendEmail(
                user.getEmail(),
                "Confirm your registration",
                emailBody
        );

        return new AuthResponse(null, request.getUsername(), user.getRole(),
                "Registration successful! Check your email to confirm.");
    }

    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));

        if (!user.isEnabled()) {
            throw new IllegalArgumentException("Email not confirmed yet");
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Invalid credentials");
        }

        String token = jwtUtil.generateToken(user);
        return new AuthResponse(token, user.getUsername(), user.getRole(), "Login successful!");
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
        userRepository.save(user);
    }

    public void resendVerificationCode(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Email not registered"));

        if (user.isEnabled()) {
            throw new IllegalArgumentException("Email already confirmed");
        }

        // Generate a new 6-digit code
        int code = new Random().nextInt(900000) + 100000;
        user.setVerificationCode(String.valueOf(code));
        user.setVerificationCodeGeneratedAt(System.currentTimeMillis());

        userRepository.save(user);

        // Send email
        String emailBody = "Your new verification code is: <b>" + user.getVerificationCode() +
                "</b>.<br>Please take note that this code will expire in 10 minutes.";
        emailService.sendEmail(
                user.getEmail(),
                "Resend verification code",
                emailBody
        );
    }
}