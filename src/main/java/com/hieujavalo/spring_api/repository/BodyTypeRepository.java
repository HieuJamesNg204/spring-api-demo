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