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