package com.app;

import com.app.repository.UserRepository;
import com.app.model.Permiso;
import com.app.model.Rol;
import com.app.model.RolEnum;
import com.app.model.Usuario;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;
import java.util.Set;

@SpringBootApplication
public class SpringSecurityAppApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityAppApplication.class, args);
	}

	@Bean
	CommandLineRunner init(UserRepository userRepository, PasswordEncoder passwordEncoder){
		return args->{
			/*creando PERMISOS*/
			Permiso createPermiso = Permiso.builder()
					.name("CREATE")
					.build();

			Permiso readPermiso = Permiso.builder()
					.name("READ")
					.build();

			Permiso updatePermiso = Permiso.builder()
					.name("UPDATE")
					.build();

			Permiso deletePermiso = Permiso.builder()
					.name("DELETE")
					.build();

			Permiso refactorPermiso = Permiso.builder()
					.name("REFACTOR")
					.build();

			/*creando ROLES*/
			Rol rolAdmin = Rol.builder()
					.rolEnum(RolEnum.ADMIN)
					.permisoList(Set.of(createPermiso,readPermiso,updatePermiso,deletePermiso))
					.build();

			Rol rolUser = Rol.builder()
					.rolEnum(RolEnum.USER)
					.permisoList(Set.of(createPermiso,readPermiso))
					.build();

			Rol rolInvited = Rol.builder()
					.rolEnum(RolEnum.INVITED)
					.permisoList(Set.of(readPermiso))
					.build();

			Rol rolDeveloper = Rol.builder()
					.rolEnum(RolEnum.DEVELOPER)
					.permisoList(Set.of(createPermiso,readPermiso,updatePermiso,deletePermiso,refactorPermiso))
					.build();

			/*
			//segunda forma si los usuarios ya existen
			//creando Usuarios
			createUserIfNotFound(userRepository, "santiago", "1234", Set.of(rolAdmin));
			createUserIfNotFound(userRepository, "carlos", "1234", Set.of(rolUser));
			createUserIfNotFound(userRepository, "roberto", "1234", Set.of(rolInvited));
			createUserIfNotFound(userRepository, "pepito", "1234", Set.of(rolDeveloper));
			*/

			//primera forma si los usuarios n oexisten
			//creando Usuarios
			Usuario user1 = Usuario.builder()
					.username("santiago")
					.password(passwordEncoder.encode("1234"))
					.isEnabled(true)
					.accountNoExpired(true)
					.accountNoLocked(true)
					.credentialNoExpired(true)
					.roles(Set.of(rolAdmin))
					.build();

			Usuario user2 = Usuario.builder()
					.username("carlos")
					.password(passwordEncoder.encode("1234"))
					.isEnabled(true)
					.accountNoExpired(true)
					.accountNoLocked(true)
					.credentialNoExpired(true)
					.roles(Set.of(rolUser))
					.build();

			Usuario user3 = Usuario.builder()
					.username("roberto")
					.password(passwordEncoder.encode("1234"))
					.isEnabled(true)
					.accountNoExpired(true)
					.accountNoLocked(true)
					.credentialNoExpired(true)
					.roles(Set.of(rolInvited))
					.build();

			Usuario user4 = Usuario.builder()
					.username("pepito")
					.password(passwordEncoder.encode("1234"))
					.isEnabled(true)
					.accountNoExpired(true)
					.accountNoLocked(true)
					.credentialNoExpired(true)
					.roles(Set.of(rolDeveloper))
					.build();

			//guardando todos los usuarios
			userRepository.saveAll(List.of(user1,user2,user3,user4));

		};

	}
	/*
	private void createUserIfNotFound(UserRepository userRepository, String username, String password, Set<Rol> roles) {
		Optional<Usuario> existingUser = userRepository.findUsuarioByUsername(username);
		if (existingUser.isPresent()) {
			System.out.println("Usuario " + username + " ya existe.");
		} else {
			Usuario user = Usuario.builder()
					.username(username)
					.password(password)
					.isEnabled(true)
					.accountNoExpired(true)
					.accountNoLocked(true)
					.credentialNoExpired(true)
					.roles(roles)
					.build();
			userRepository.save(user);
		}
	}
*/
}
