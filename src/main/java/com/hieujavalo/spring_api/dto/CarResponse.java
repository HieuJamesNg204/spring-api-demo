package com.hieujavalo.spring_api.dto;

import com.hieujavalo.spring_api.entity.Car;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CarResponse {
    private Long id;
    private String make;
    private String model;
    private Long bodyTypeId;
    private String bodyTypeName;

    public static CarResponse fromCar(Car car) {
        return new CarResponse(
                car.getId(),
                car.getMake(),
                car.getModel(),
                car.getBodyType().getId(),
                car.getBodyType().getName()
        );
    }
}