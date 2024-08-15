package com.app.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/method")
//@PreAuthorize("denyAll()") //deniega acceso atodos //esto se quita si se usa de la otra forma
public class TestAuthController {

    @GetMapping("/get")
    //@PreAuthorize("hasAuthority('READ')")//esto se quita si se usa de la otra forma
    public String helloGet(){
        return "hello world - GET ";
    }

    @PostMapping("/post")
    //@PreAuthorize("hasAuthority('CREATE') or hasAuthority('READ')")//esto se quita si se usa de la otra forma
    public String helloPost(){
        return "Hello world - POST";
    }

    @PutMapping("/put")
    public String helloPut(){
        return "Hello world - PUT";
    }
    @DeleteMapping("/delete")
    //@PreAuthorize("hasAuthority('CREATE') or hasAuthority('READ')")//esto se quita si se usa de la otra forma
    public String helloDelete(){
        return "Hello world - DELETE";
    }

    @PatchMapping("/patch")
    //@PreAuthorize("hasAuthority('REFACTOR')")//esto se quita si se usa de la otra forma
    public String helloPatch(){
        return "Hello world - PATCH";
    }
}
