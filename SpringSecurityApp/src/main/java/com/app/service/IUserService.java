package com.app.service;

import com.app.model.Usuario;

import java.util.Optional;

public interface IUserService {

    Optional<Usuario> findUsuarioByUsername(String username);
}
