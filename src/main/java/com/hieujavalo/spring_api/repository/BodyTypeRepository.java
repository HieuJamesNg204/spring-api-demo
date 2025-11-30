package com.hieujavalo.spring_api.repository;

import com.hieujavalo.spring_api.entity.BodyType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BodyTypeRepository extends JpaRepository<BodyType, Long> {
}