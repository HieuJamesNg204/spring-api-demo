package com.hieujavalo.spring_api.dto;

import com.hieujavalo.spring_api.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UpdateUserRequest {
    private String email;
    private String password;
    private Role role;
}