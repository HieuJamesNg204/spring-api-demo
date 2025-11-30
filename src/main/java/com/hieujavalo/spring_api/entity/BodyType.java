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