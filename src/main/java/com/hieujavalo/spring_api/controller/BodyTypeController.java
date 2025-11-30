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