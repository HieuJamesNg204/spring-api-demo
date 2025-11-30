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