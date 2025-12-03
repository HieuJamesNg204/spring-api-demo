package com.hieujavalo.spring_api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ResetPasswordRequest {
    @NotBlank(message = "Code is required")
    private String code;

    @NotBlank(message = "Password is required")
    private String password;
}