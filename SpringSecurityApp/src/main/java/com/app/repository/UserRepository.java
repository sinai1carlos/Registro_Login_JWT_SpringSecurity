package com.app.repository;

import com.app.model.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<Usuario,Long> {
    /*1ra forma*/
    Optional<Usuario> findUsuarioByUsername(String username);

    /*2ra forma*//*
    @Query("SELECT u FROM Usuario u WHERE u.username= ?")
    Optional<Usuario> findUser(String username);*/
}
