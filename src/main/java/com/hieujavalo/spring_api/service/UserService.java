package com.hieujavalo.spring_api.service;

import com.hieujavalo.spring_api.dto.CreateUserRequest;
import com.hieujavalo.spring_api.dto.UpdateUserRequest;
import com.hieujavalo.spring_api.dto.UserResponse;
import com.hieujavalo.spring_api.entity.User;
import com.hieujavalo.spring_api.exception.ResourceNotFoundException;
import com.hieujavalo.spring_api.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public List<UserResponse> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .map(UserResponse::fromUser)
                .collect(Collectors.toList());
    }

    public UserResponse getUserById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        return UserResponse.fromUser(user);
    }

    public UserResponse addUser(CreateUserRequest request) {
        System.out.println(request.getRole());

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(request.getRole());
        user.setEnabled(true);

        User savedUser = userRepository.save(user);
        return UserResponse.fromUser(savedUser);
    }

    public UserResponse updateUser(Long id, UpdateUserRequest request) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (request.getEmail() != null && !request.getEmail().isBlank()) {
            user.setEmail(request.getEmail());
        }

        if (request.getRole() != null) {
            user.setRole(request.getRole());
        }

        if (request.getPassword() != null && !request.getPassword().isBlank()) {
            user.setPassword(passwordEncoder.encode(request.getPassword()));
        }

        User savedUser = userRepository.save(user);
        return UserResponse.fromUser(savedUser);
    }

    public void deleteUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        userRepository.delete(user);
    }
}