package com.hieujavalo.spring_api.dto;

import com.hieujavalo.spring_api.entity.BodyType;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.stream.Collectors;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class BodyTypeResponse {
    private Long id;
    private String name;
    private List<CarResponse> cars;

    public static BodyTypeResponse fromBodyType(BodyType bodyType) {
        return new BodyTypeResponse(
                bodyType.getId(),
                bodyType.getName(),
                bodyType.getCars()
                        .stream()
                        .map(CarResponse::fromCar)
                        .collect(Collectors.toList())
        );
    }
}