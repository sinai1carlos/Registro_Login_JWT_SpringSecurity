package com.app.security;

import com.app.security.filter.JwtTokenValidator;
import com.app.service.UserService;
import com.app.util.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.util.ArrayList;
import java.util.List;

@EnableWebSecurity
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private JwtUtils jwtUtils;

    //primera forma basica

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf-> csrf.disable())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(httpR->{
                            //configurar los endpoint publicos
                            httpR.requestMatchers(HttpMethod.POST,"/auth/**").permitAll();
                            //configurar los endpoints privados
                            //para roles
                            httpR.requestMatchers(HttpMethod.POST,"/method/post").hasRole("ADMIN");//rol para 1
                            httpR.requestMatchers(HttpMethod.POST,"/method/post").hasAnyRole("ADMIN","DEVELOPER");//rol para varios
                            //para permisos
                            httpR.requestMatchers(HttpMethod.GET,"/method/get").hasAuthority("CREATE");//permiso para 1
                            httpR.requestMatchers(HttpMethod.PATCH,"/method/patch").hasAnyAuthority("CREATE","READ");//permiso para varios
                            //configurar el resto de endpoints - NO ESPECIFICADOS
                            httpR.anyRequest().denyAll();
                        }
                        )
                  .addFilterBefore(new JwtTokenValidator(jwtUtils), BasicAuthenticationFilter.class);
        return http.build();
    }
    //segunda forma
    /*
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf-> csrf.disable())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(new JwtTokenValidator(jwtUtils), BasicAuthenticationFilter.class);

        return http.build();
    }*/

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }


    /*esto es para traerlos desde la base de datos y no usar el userdetailservice de ahi abajo*/
    @Bean
    public AuthenticationProvider authenticationProvider(UserService userService){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder());
        provider.setUserDetailsService(userService);
        return provider;
    }

    /*esto es para traerlo y ponerlo en memoria
    @Bean
    public UserDetailsService userDetailsService(){
        List<UserDetails> userDetails = new ArrayList<>();

        userDetails.add(User.withUsername("sinai1")
                .password("1234")
                .roles("ADMIN")
                .authorities("READ","CREATE")
                .build());

        userDetails.add(User.withUsername("carlos1")
                .password("1234")
                .roles("ADMIN")
                .authorities("READ")
                .build());

        return new InMemoryUserDetailsManager(userDetails);
    }*/



    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


}
