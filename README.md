# 9. Customer updating emails and passwords
## Step 1: Update User entity
First, add some fields for `User` to handle email change, with `pendingEmail` used for saving the new email that has not verified yet.
**entity/User.java**
```java
package com.hieujavalo.spring_api.entity;

import com.hieujavalo.spring_api.enums.Role;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "user")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private Role role;

    @Column
    private String verificationCode;

    @Column
    private Long verificationCodeGeneratedAt;

    @Column
    private String resetPasswordCode;

    @Column
    private Long resetPasswordCodeGeneratedAt;

    @Column
    private String emailChangeCode;

    @Column
    private Long emailChangeCodeGeneratedAt;

    @Column
    private String pendingEmail;

    @Column
    private boolean isEnabled = false;
}
```
## Step 2: Create a new DTO
Add a new DTO for password change request.
**dto/ChangePasswordRequest.java**
```java
package com.hieujavalo.spring_api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ChangePasswordRequest {
    @NotBlank(message = "Current password is required")
    private String currentPassword;

    @NotBlank(message = "New password is required")
    @Size(min = 8, message = "Password must be at least 8 characters long")
    private String newPassword;
}
```
## Step 3: Update authentication service
Update `AuthService` to handle email and password change logics.
**service/AuthService.java**
```java
package com.hieujavalo.spring_api.service;

import com.hieujavalo.spring_api.dto.*;
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
## Step 4: Update controllers
Update `AuthController` to add new endpoints for email and password change.
**controller/AuthController.java**
```java
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
```
## Step 5: Update security configuration
Update `SecurityConfig` to add new rules so that we can make sure that the new features we've just added are used only by authenticated users.
**config/SecurityConfig.java**
```java
package com.hieujavalo.spring_api.config;

import com.hieujavalo.spring_api.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtAuthenticationEntryPoint unauthorizedHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:3000"));
        config.setAllowedMethods(List.of("GET","POST","PUT","DELETE","PATCH"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                        .requestMatchers("/api/v1/auth/profile").authenticated()
                        .requestMatchers("/api/v1/auth/change-email/**").authenticated()
                        .requestMatchers("/api/v1/auth/change-password").authenticated()
                        .requestMatchers("/api/v1/auth/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/**").permitAll()
                        .anyRequest().authenticated()
                )
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(unauthorizedHandler)
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
```
## Step 6: Run application
Now run your application and test the newly added features.