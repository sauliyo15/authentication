package com.sauliyo15.autenticacion.service.impl;

import com.sauliyo15.autenticacion.dto.JwtResponse;
import com.sauliyo15.autenticacion.dto.LoginRequest;
import com.sauliyo15.autenticacion.dto.SingUpRequest;
import com.sauliyo15.autenticacion.entities.UserEntity;
import com.sauliyo15.autenticacion.repository.UserRepository;
import com.sauliyo15.autenticacion.util.SecurityUtils;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.BadRequestException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final UserServiceImpl userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public JwtResponse signup(SingUpRequest request) throws BadRequestException {

        // Verificación del email existente
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new BadRequestException("El email ya está registrado.");
        }

        var user = UserEntity
                .builder()
                .name(request.getName())
                .surname(request.getSurname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role("ROLE_CLIENT")
                .build();
        user = userService.save(user);
        var jwt = jwtService.generateToken(user);
        return JwtResponse.builder().token(jwt).build();
    }

    public JwtResponse login(LoginRequest request) {

        // Verificar si ya está autenticado antes de permitir login
        if (SecurityUtils.getAuthenticatedUser() != null) {
            throw new IllegalStateException("Ya estás autenticado");
        }

        // Verificar si el usuario existe
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));

        // Verificar si la contraseña es correcta
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Contraseña incorrecta");
        }

        // Autenticación exitosa
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        var jwt = jwtService.generateToken(user);
        return JwtResponse.builder().token(jwt).build();
    }
}
