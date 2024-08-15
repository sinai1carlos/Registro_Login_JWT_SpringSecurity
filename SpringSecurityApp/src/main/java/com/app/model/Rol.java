package com.app.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashSet;
import java.util.Set;

@Entity
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Table(name="roles")
public class Rol {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name="rol_name")
    @Enumerated(EnumType.STRING)
    private RolEnum rolEnum;

    @ManyToMany(fetch = FetchType.EAGER,cascade = CascadeType.ALL)
    @JoinTable(name = "rol_permisos",joinColumns = @JoinColumn(name="rol_id"),inverseJoinColumns = @JoinColumn(name="permiso_id"))
    private Set<Permiso> permisoList = new HashSet<>();

}
