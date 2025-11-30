package com.hieujavalo.spring_api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CreateCarRequest {
    @NotBlank(message = "make is required")
    private String make;

    @NotBlank(message = "model is required")
    private String model;

    @NotNull(message = "bodyTypeId is required")
    private Long bodyTypeId;
}