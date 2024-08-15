package com.app.service;

import com.app.controller.dto.AuthCreateUserRequest;
import com.app.controller.dto.AuthLoginRequest;
import com.app.controller.dto.AuthResponse;
import com.app.model.Rol;
import com.app.repository.RolRepository;
import com.app.repository.UserRepository;
import com.app.model.Usuario;
import com.app.util.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RolRepository rolRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Usuario user = userRepository.findUsuarioByUsername(username)
                .orElseThrow(()-> new UsernameNotFoundException("El usuario "+username+"  no existe."));
        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();

        user.getRoles()
                .forEach(rol -> authorityList.add(new SimpleGrantedAuthority("ROLE_".concat(rol.getRolEnum().name()))));

        user.getRoles().stream()
                .flatMap(rol ->rol.getPermisoList().stream())
                .forEach(permiso -> authorityList.add(new SimpleGrantedAuthority(permiso.getName())));

        return new User(user.getUsername(),
                user.getPassword(),
                user.isEnabled(),
                user.isAccountNoExpired(),
                user.isCredentialNoExpired(),
                user.isAccountNoLocked(),authorityList);
    }

    public AuthResponse loginUser(AuthLoginRequest authLoginRequest){
        String username = authLoginRequest.username();
        String password = authLoginRequest.password();

        Authentication authentication = authenticate(username,password);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String accessToken =jwtUtils.createToken(authentication);

        AuthResponse authResponse = new AuthResponse(username,"User loged successfuly",accessToken,true);

        return authResponse;
    }

    public Authentication authenticate(String username, String password){
        UserDetails userDetails = loadUserByUsername(username);

        if(userDetails==null){
            throw new BadCredentialsException("Invalid username or password.");
        }

        if(!passwordEncoder.matches(password,userDetails.getPassword())){
            throw new BadCredentialsException("Invalid password.");
        }

        return new UsernamePasswordAuthenticationToken(username,userDetails.getPassword(),userDetails.getAuthorities());
    }

    public AuthResponse createUser(AuthCreateUserRequest authCreateUserRequest){
        String username = authCreateUserRequest.username();
        String password = authCreateUserRequest.password();
        List<String > rolRequest = authCreateUserRequest.rolRequest().rolListName();

        Set<Rol> rolSet = rolRepository.findRolByRolEnumIn(rolRequest).stream().collect(Collectors.toSet());

        if(rolSet.isEmpty()){
            throw new IllegalArgumentException("Los roles especificados no existen");
        }

        Usuario usuarioNuevo = Usuario.builder()
                .username(username)
                .password(passwordEncoder.encode(password))
                .roles(rolSet)
                .isEnabled(true)
                .accountNoLocked(true)
                .accountNoExpired(true)
                .credentialNoExpired(true)
                .build();

       Usuario usuarioCreado = userRepository.save(usuarioNuevo);
       ArrayList<SimpleGrantedAuthority> authorityList = new ArrayList<>();

       usuarioCreado.getRoles().forEach(rol -> authorityList.add(new SimpleGrantedAuthority("ROLE_".concat(rol.getRolEnum().name()))));

       usuarioCreado.getRoles()
               .stream()
               .flatMap(rol -> rol.getPermisoList().stream())
               .forEach(permiso ->authorityList.add(new SimpleGrantedAuthority(permiso.getName())));
        Authentication authentication = new UsernamePasswordAuthenticationToken(usuarioCreado.getUsername(),usuarioCreado.getPassword(),authorityList);

        String accessToken =jwtUtils.createToken(authentication);

        AuthResponse authResponse = new AuthResponse(usuarioCreado.getUsername(),"Usuari ocreado correctamente",accessToken,true);
        return authResponse ;
    }
}
