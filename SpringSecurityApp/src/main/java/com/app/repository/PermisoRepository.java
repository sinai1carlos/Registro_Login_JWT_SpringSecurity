package com.app.repository;

import com.app.model.Permiso;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PermisoRepository extends JpaRepository<Permiso, Long> {
    // Puedes agregar métodos personalizados si lo necesitas.
}
