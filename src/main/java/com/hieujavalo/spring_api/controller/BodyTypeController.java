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