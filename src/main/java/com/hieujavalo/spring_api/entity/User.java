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
    private boolean isEnabled = false; // default false
}