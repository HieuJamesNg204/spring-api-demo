# 1. Basic Spring Boot
## Step 1: Set up the project
First, go to [Spring Initializr](spring.application.name=spring_api) to initialise a new project.
<img width="752" height="871" alt="image" src="https://github.com/user-attachments/assets/e848cc74-1173-42fe-b9dd-49c8bdae5583" />

After clicking the generate button, save the project anywhere you want. Then, open IntelliJ IDEA, and open the project you've saved.
Next, add a dependency to pom.xml
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>4.0.0</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>
	<groupId>com.hieujavalo</groupId>
	<artifactId>spring_api</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>spring_api</name>
	<description>Demo project for Spring Boot</description>
	<url/>
	<licenses>
		<license/>
	</licenses>
	<developers>
		<developer/>
	</developers>
	<scm>
		<connection/>
		<developerConnection/>
		<tag/>
		<url/>
	</scm>
	<properties>
		<java.version>21</java.version>
	</properties>
	<dependencies>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>
	</dependencies>

	<build>
		<plugins>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
			</plugin>
		</plugins>
	</build>

</project>
```
## Step 2: Design a structure for your project
Organise your project as below
```
main/
├── java/
│   └── com/hieujavalo/spring_api/
│       ├── controller/
│       │   ├── BodyTypeController.java
│       │   └── CarController.java
│       ├── entity/
│       │   ├── BodyType.java
│       │   └── Car.java
│       ├── repository/
│       │   ├── BodyTypeRepository.java
│       │   └── CarRepository.java
│       ├── service/
│       │   ├── BodyTypeService.java
│       │   └── CarService.java
│       └── SpringBootApiApplication.java
└── resources/
    └── application.properties
```
## Step 3: Create entities
Define BodyType and Car. First, the project will use in-memory data storage, and database will be implemented later.
**entity/BodyType.java**
```java
package com.hieujavalo.spring_api.entity;

public class BodyType {
    private Long id;
    private String name;

    public BodyType() {}

    public BodyType(Long id, String name) {
        this.id = id;
        this.name = name;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
```
**entity/Car.java**
```java
package com.hieujavalo.spring_api.entity;

public class Car {
    private Long id;
    private String make;
    private String model;
    private BodyType bodyType;

    public Car() {}

    public Car(Long id, String make, String model, BodyType bodyType) {
        this.id = id;
        this.make = make;
        this.model = model;
        this.bodyType = bodyType;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getMake() {
        return make;
    }

    public void setMake(String make) {
        this.make = make;
    }

    public String getModel() {
        return model;
    }

    public void setModel(String model) {
        this.model = model;
    }

    public BodyType getBodyType() {
        return bodyType;
    }

    public void setBodyType(BodyType bodyType) {
        this.bodyType = bodyType;
    }
}
```
## Step 4: Create repository
Define repository for saving data.
**repository/BodyTypeRepository.java**
```java
package com.hieujavalo.spring_api.repository;

import com.hieujavalo.spring_api.entity.BodyType;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Repository
public class BodyTypeRepository {
    private List<BodyType> bodyTypes = new ArrayList<>();
    private Long idCounter = 1L;

    public List<BodyType> findAll() {
        return bodyTypes;
    }

    public Optional<BodyType> findById(Long id) {
        return bodyTypes.stream().filter(bt -> bt.getId().equals(id)).findFirst();
    }

    public BodyType save(BodyType bodyType) {
        if (bodyType.getId() == null) {
            bodyType.setId(idCounter++);
        } else {
            deleteById(bodyType.getId());
        }
        bodyTypes.add(bodyType);
        return bodyType;
    }

    public void deleteById(Long id) {
        bodyTypes.removeIf(bt -> bt.getId().equals(id));
    }
}
```
**repository/CarRepository.java**
```java
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
```
## Step 5: Create services
**service/BodyTypeService.java**
```java
package com.hieujavalo.spring_api.service;

import com.hieujavalo.spring_api.entity.BodyType;
import com.hieujavalo.spring_api.repository.BodyTypeRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class BodyTypeService {
    private final BodyTypeRepository bodyTypeRepository;

    public BodyTypeService(BodyTypeRepository bodyTypeRepository) {
        this.bodyTypeRepository = bodyTypeRepository;
    }

    public List<BodyType> getAllBodyTypes() {
        return bodyTypeRepository.findAll();
    }

    public Optional<BodyType> getBodyTypeById(Long id) {
        return bodyTypeRepository.findById(id);
    }

    public BodyType addBodyType(BodyType bodyType) {
        return bodyTypeRepository.save(bodyType);
    }

    public BodyType updateBodyType(Long id, BodyType bodyType) {
        bodyType.setId(id);
        return bodyTypeRepository.save(bodyType);
    }

    public void deleteBodyType(Long id) {
        bodyTypeRepository.deleteById(id);
    }
}
```
**service/CarService.java**
```java
package com.hieujavalo.spring_api.service;

import com.hieujavalo.spring_api.entity.Car;
import com.hieujavalo.spring_api.repository.CarRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class CarService {
    private final CarRepository carRepository;

    public CarService(CarRepository carRepository) {
        this.carRepository = carRepository;
    }

    public List<Car> getAllCars() {
        return carRepository.findAll();
    }

    public Optional<Car> getCarById(Long id) {
        return carRepository.findById(id);
    }

    public Car addCar(Car car) {
        return carRepository.save(car);
    }

    public Car updateCar(Long id, Car car) {
        car.setId(id);
        return carRepository.save(car);
    }

    public void deleteCar(Long id) {
        carRepository.deleteById(id);
    }
}
```
## Step 6: Create controllers
Define controllers with mapping.
**controller/BodyTypeController.java**
```java
package com.hieujavalo.spring_api.controller;

import com.hieujavalo.spring_api.entity.BodyType;
import com.hieujavalo.spring_api.service.BodyTypeService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/bodytypes")
public class BodyTypeController {
    private final BodyTypeService bodyTypeService;

    public BodyTypeController(BodyTypeService bodyTypeService) {
        this.bodyTypeService = bodyTypeService;
    }

    @GetMapping
    public List<BodyType> getAllBodyTypes() {
        return bodyTypeService.getAllBodyTypes();
    }

    @GetMapping("/{id}")
    public ResponseEntity<BodyType> getBodyTypeById(@PathVariable Long id) {
        return bodyTypeService.getBodyTypeById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public BodyType addBodyType(@RequestBody BodyType bodyType) {
        return bodyTypeService.addBodyType(bodyType);
    }

    @PutMapping("/{id}")
    public ResponseEntity<BodyType> updateBodyType(@PathVariable Long id, @RequestBody BodyType bodyType) {
        return bodyTypeService.getBodyTypeById(id)
                .map(existing -> ResponseEntity.ok(bodyTypeService.updateBodyType(id, bodyType)))
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteBodyType(@PathVariable Long id) {
        return bodyTypeService.getBodyTypeById(id)
                .map(existing -> {
                    bodyTypeService.deleteBodyType(id);
                    return ResponseEntity.noContent().<Void>build();
                })
                .orElse(ResponseEntity.notFound().build());
    }
}
```
**controller/CarController.java**
```java
package com.hieujavalo.spring_api.controller;

import com.hieujavalo.spring_api.entity.Car;
import com.hieujavalo.spring_api.service.CarService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/cars")
public class CarController {
    private final CarService carService;

    public CarController(CarService carService) {
        this.carService = carService;
    }

    @GetMapping
    public List<Car> getAllCars() {
        return carService.getAllCars();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Car> getCarById(@PathVariable Long id) {
        return carService.getCarById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public Car addCar(@RequestBody Car car) {
        return carService.addCar(car);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Car> updateCar(@PathVariable Long id, @RequestBody Car car) {
        return carService.getCarById(id)
                .map(existingCar -> ResponseEntity.ok(carService.updateCar(id, car)))
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteCar(@PathVariable Long id) {
        return carService.getCarById(id)
                .map(existingCar -> {
                    carService.deleteCar(id);
                    return ResponseEntity.noContent().<Void>build();
                })
                .orElse(ResponseEntity.notFound().build());
    }
}
```
## Step 7: Run application
Open **SpringBootApiApplication.java** and click the triangle button to run.
