# 2. Integrating MySQL, and polishing the project
## Step 1: Add some dependencies
First, add the necessary dependencies to **pom.xml**:
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
<dependency>
    <groupId>com.mysql</groupId>
    <artifactId>mysql-connector-j</artifactId>
    <version>8.2.0</version>
</dependency>
<dependency>
    <groupId>org.projectlombok</groupId>
    <artifactId>lombok</artifactId>
    <optional>true</optional>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>
```
## Step 2: Configure your application.properties
To set up MySQL connection, add these lines to **main/resources/application.properties**
```
spring.application.name=spring_boot_api

spring.datasource.url=jdbc:mysql://localhost:3306/your_database
spring.datasource.username=your_username
spring.datasource.password=your_password
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver

spring.jpa.hibernate.ddl-auto=update
spring.jpa.database-platform=org.hibernate.dialect.MySQLDialect
spring.jpa.show-sql=false
```
Remember to replace ```your_database``` with your actual database's name, ```your_username``` with your actual database username, and ```your_password``` with your actual database password.
## Step 3: Update entities with MySQL
Update the ```BodyType``` and ```Car``` classes integrating MySQL database.
**entity/BodyType.java**
```java
package com.hieujavalo.spring_api.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "body_type")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class BodyType {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @OneToMany(mappedBy = "bodyType", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Car> cars = new ArrayList<>();
}
```
**entity/Car.java**
```java
package com.hieujavalo.spring_api.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "car")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Car {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String make;

    @Column(nullable = false)
    private String model;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "body_type_id", nullable = false)
    private BodyType bodyType;
}
```
## Step 6: Create DTOs
Create DTOs to handle requests and responses better.
**dto/CreateBodyTypeRequest.java**
```java
package com.hieujavalo.spring_api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CreateBodyTypeRequest {
    @NotBlank(message = "name is required")
    private String name;
}
```
**dto/UpdateBodyTypeRequest.java**
```java
package com.hieujavalo.spring_api.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UpdateBodyTypeRequest {
    private String name;
}
```
**dto/BodyTypeResponse.java**
```java
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
```
**dto/CreateCarRequest.java**
```java
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
```
**dto/UpdateCarRequest.java**
```java
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
```
**dto/CarResponse.java**
```java
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
```
## Step 5: Create and handle exceptions
Create a custom exception to throw when the application fails to retrieve data.
**exception/ResourceNotFoundException.java**
```java
package com.hieujavalo.spring_api.exception;

public class ResourceNotFoundException extends RuntimeException {
    public ResourceNotFoundException(String message) {
        super(message);
    }
}
```
Now create a handler to handle exceptions.
**exception/GlobalExceptionHandler.java**
```java
package com.hieujavalo.spring_api.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<?> handleNotFound(ResourceNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", ex.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<?> handleBadRequest(IllegalArgumentException ex) {
        return ResponseEntity.badRequest()
                .body(Map.of("error", ex.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidationExceptions(
            MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();

        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errors);
    }
}
```
## Step 6: Update repositories
Update the repositories to save data in MySQL with ```JpaRepository``` instead of in-memory List.
**repository/BodyTypeRepository.java**
```java
package com.hieujavalo.spring_api.repository;

import com.hieujavalo.spring_api.entity.BodyType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BodyTypeRepository extends JpaRepository<BodyType, Long> {
}
```
**repository/CarRepository.java**
```java
package com.hieujavalo.spring_api.repository;

import com.hieujavalo.spring_api.entity.Car;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CarRepository extends JpaRepository<Car, Long> {
}
```
## Step 7: Update services
Update ```BodyTypeService``` and ```CarService``` with the integration of MySQL.
**service/BodyTypeService.java**
```java
package com.hieujavalo.spring_api.service;

import com.hieujavalo.spring_api.dto.BodyTypeResponse;
import com.hieujavalo.spring_api.dto.CreateBodyTypeRequest;
import com.hieujavalo.spring_api.dto.UpdateBodyTypeRequest;
import com.hieujavalo.spring_api.entity.BodyType;
import com.hieujavalo.spring_api.exception.ResourceNotFoundException;
import com.hieujavalo.spring_api.repository.BodyTypeRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class BodyTypeService {
    private final BodyTypeRepository bodyTypeRepository;

    public List<BodyTypeResponse> getAllBodyTypes() {
        return bodyTypeRepository.findAll()
                .stream()
                .map(BodyTypeResponse::fromBodyType)
                .collect(Collectors.toList());
    }

    public BodyTypeResponse getBodyTypeById(Long id) {
        BodyType bodyType = bodyTypeRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Body type not found"));
        return BodyTypeResponse.fromBodyType(bodyType);
    }

    public BodyTypeResponse addBodyType(CreateBodyTypeRequest request) {
        BodyType bodyType = new BodyType();
        bodyType.setName(request.getName());
        BodyType savedBodyType = bodyTypeRepository.save(bodyType);
        return BodyTypeResponse.fromBodyType(savedBodyType);
    }

    public BodyTypeResponse updateBodyType(Long id, UpdateBodyTypeRequest request) {
        BodyType bodyType = bodyTypeRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Body type not found"));

        if (request.getName() != null && !request.getName().isBlank()) {
            bodyType.setName(request.getName());
        }

        BodyType updatedBodyType = bodyTypeRepository.save(bodyType);
        return BodyTypeResponse.fromBodyType(updatedBodyType);
    }

    public void deleteBodyType(Long id) {
        BodyType bodyType = bodyTypeRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Body type not found"));
        bodyTypeRepository.delete(bodyType);
    }
}
```
**service/CarService.java**
```java
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
```
## Step 8: Update controllers
Finally, update the two controllers after all changes we've made.
**controller/BodyTypeController.java**
```java
package com.hieujavalo.spring_api.controller;

import com.hieujavalo.spring_api.dto.BodyTypeResponse;
import com.hieujavalo.spring_api.dto.CreateBodyTypeRequest;
import com.hieujavalo.spring_api.dto.UpdateBodyTypeRequest;
import com.hieujavalo.spring_api.service.BodyTypeService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/bodytypes")
@RequiredArgsConstructor
@Slf4j
public class BodyTypeController {
    private final BodyTypeService bodyTypeService;

    @GetMapping
    public ResponseEntity<List<BodyTypeResponse>> getAllBodyTypes() {
        List<BodyTypeResponse> bodyTypes = bodyTypeService.getAllBodyTypes();
        return ResponseEntity.ok(bodyTypes);
    }

    @GetMapping("/{id}")
    public ResponseEntity<BodyTypeResponse> getBodyTypeById(@PathVariable Long id) {
        BodyTypeResponse bodyType = bodyTypeService.getBodyTypeById(id);
        return ResponseEntity.ok(bodyType);
    }

    @PostMapping
    public ResponseEntity<BodyTypeResponse> addBodyType(@Valid @RequestBody CreateBodyTypeRequest request) {
        BodyTypeResponse response = bodyTypeService.addBodyType(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PutMapping("/{id}")
    public ResponseEntity<BodyTypeResponse> updateBodyType(@PathVariable Long id, @RequestBody UpdateBodyTypeRequest request) {
        BodyTypeResponse response = bodyTypeService.updateBodyType(id, request);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteBodyType(@PathVariable Long id) {
        bodyTypeService.deleteBodyType(id);
    }
}
```
**controller/CarController.java**
```java
package com.hieujavalo.spring_api.controller;

import com.hieujavalo.spring_api.dto.CarResponse;
import com.hieujavalo.spring_api.dto.CreateCarRequest;
import com.hieujavalo.spring_api.dto.UpdateCarRequest;
import com.hieujavalo.spring_api.service.CarService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/cars")
@RequiredArgsConstructor
@Slf4j
public class CarController {
    private final CarService carService;

    @GetMapping
    public ResponseEntity<List<CarResponse>> getAllCars() {
        List<CarResponse> cars = carService.getAllCars();
        return ResponseEntity.ok(cars);
    }

    @GetMapping("/{id}")
    public ResponseEntity<CarResponse> getCarById(@PathVariable Long id) {
        CarResponse car = carService.getCarById(id);
        return ResponseEntity.ok(car);
    }

    @PostMapping
    public ResponseEntity<CarResponse> addCar(@Valid @RequestBody CreateCarRequest request) {
        CarResponse response = carService.addCar(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PutMapping("/{id}")
    public ResponseEntity<CarResponse> updateCar(@PathVariable Long id, @RequestBody UpdateCarRequest request) {
        CarResponse response = carService.updateCar(id, request);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteCar(@PathVariable Long id) {
        carService.deleteCar(id);
    }
}

```
## Step 9: Run application
Now open **SpringBootApiApplication.java** and click the triangle button to run.