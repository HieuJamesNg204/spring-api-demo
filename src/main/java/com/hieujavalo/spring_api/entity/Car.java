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