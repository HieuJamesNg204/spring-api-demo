package com.hieujavalo.spring_api.dto;

import com.hieujavalo.spring_api.entity.User;
import com.hieujavalo.spring_api.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserResponse {
    private Long id;
    private String username;
    private String email;
    private Role role;

    public static UserResponse fromUser(User user) {
        return new UserResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getRole()
        );
    }
}