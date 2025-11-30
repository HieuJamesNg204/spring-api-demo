package com.hieujavalo.spring_api.service;

import com.hieujavalo.spring_api.dto.CarResponse;
import com.hieujavalo.spring_api.dto.CreateCarRequest;
import com.hieujavalo.spring_api.dto.UpdateCarRequest;
import com.hieujavalo.spring_api.entity.BodyType;
import com.hieujavalo.spring_api.entity.Car;
import com.hieujavalo.spring_api.exception.ResourceNotFoundException;
import com.hieujavalo.spring_api.repository.BodyTypeRepository;
import com.hieujavalo.spring_api.repository.CarRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class CarService {
    private final CarRepository carRepository;
    private final BodyTypeRepository bodyTypeRepository;

    public List<CarResponse> getAllCars() {
        return carRepository.findAll()
                .stream()
                .map(CarResponse::fromCar)
                .collect(Collectors.toList());
    }

    public CarResponse getCarById(Long id) {
        Car car = carRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Car not found"));
        return CarResponse.fromCar(car);
    }

    public CarResponse addCar(CreateCarRequest request) {
        BodyType bodyType = bodyTypeRepository.findById(request.getBodyTypeId())
                .orElseThrow(() -> new ResourceNotFoundException("Body type not found"));
        Car car = new Car();

        car.setMake(request.getMake());
        car.setModel(request.getModel());
        car.setBodyType(bodyType);

        Car savedCar = carRepository.save(car);
        return CarResponse.fromCar(savedCar);
    }

    public CarResponse updateCar(Long id, UpdateCarRequest request) {
        Car car = carRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Car not found"));

        if (request.getMake() != null && !request.getMake().isBlank()) {
            car.setMake(request.getMake());
        }

        if (request.getModel() != null && !request.getModel().isBlank()) {
            car.setModel(request.getModel());
        }

        if (request.getBodyTypeId() != null) {
            BodyType bodyType = bodyTypeRepository.findById(request.getBodyTypeId())
                    .orElseThrow(() -> new ResourceNotFoundException("Body type not found"));
            car.setBodyType(bodyType);
        }

        Car updatedCar = carRepository.save(car);
        return CarResponse.fromCar(updatedCar);
    }

    public void deleteCar(Long id) {
        Car car = carRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Car not found"));
        carRepository.delete(car);
    }
}