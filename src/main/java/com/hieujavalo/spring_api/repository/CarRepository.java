package com.hieujavalo.spring_api.repository;

import com.hieujavalo.spring_api.entity.Car;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Repository
public class CarRepository {
    private List<Car> cars = new ArrayList<>();
    private Long idCounter = 1L;

    public List<Car> findAll() {
        return cars;
    }

    public Optional<Car> findById(Long id) {
        return cars.stream().filter(car -> car.getId().equals(id)).findFirst();
    }

    public Car save(Car car) {
        if (car.getId() == null) {
            car.setId(idCounter++);
        } else {
            deleteById(car.getId());
        }
        cars.add(car);
        return car;
    }

    public void deleteById(Long id) {
        cars.removeIf(car -> car.getId().equals(id));
    }
}