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
        String code = String.format("%06d", new Random().nextInt(1000000));
        user.setVerificationCode(code);
        user.setVerificationCodeGeneratedAt(System.currentTimeMillis());

        if (isAdmin && request.getRole() != null) {
            user.setRole(request.getRole());
        } else {
            user.setRole(Role.CUSTOMER);
        }

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
                + "<p>This code will expire in 5 minutes for security purposes.</p>"
                + "<p>If you did not request this, you can safely ignore the email.</p>"
                + "<p>Best regards,<br/>Your Support Team</p>";
        emailService.sendEmail(user.getEmail(), "Password Reset Request", message);
    }

    public void resetPassword(String code, String newPassword) {
        User user = userRepository.findByResetPasswordCode(code)
                .orElseThrow(() -> new IllegalArgumentException("Invalid reset code"));

        long now = System.currentTimeMillis();
        if (user.getResetPasswordCodeGeneratedAt() == null ||
                now - user.getResetPasswordCodeGeneratedAt() > 5 * 60 * 1000) { // 5 min
            throw new IllegalArgumentException("Reset code expired");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setResetPasswordCode(null);
        user.setResetPasswordCodeGeneratedAt(null);
        userRepository.save(user);
    }
}