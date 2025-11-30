package com.hieujavalo.spring_api.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UpdateCarRequest {
    private String make;
    private String model;
    private Long bodyTypeId;
}