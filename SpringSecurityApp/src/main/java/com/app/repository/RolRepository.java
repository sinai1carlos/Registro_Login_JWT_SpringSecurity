package com.app.repository;

import com.app.model.Rol;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RolRepository extends JpaRepository<Rol, Long> {
    // Puedes agregar métodos personalizados si lo necesitas.
    List<Rol> findRolByRolEnumIn(List<String> roleName);
}
