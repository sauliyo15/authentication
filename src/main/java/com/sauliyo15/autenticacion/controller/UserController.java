package com.sauliyo15.autenticacion.controller;

import com.sauliyo15.autenticacion.dto.LoginRequest;
import com.sauliyo15.autenticacion.dto.SingUpRequest;
import com.sauliyo15.autenticacion.entities.UserEntity;
import com.sauliyo15.autenticacion.service.UserService;
import com.sauliyo15.autenticacion.service.impl.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping
@RequiredArgsConstructor
public class UserController {

   private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<?> register (@RequestBody SingUpRequest request) {
        try {
            return ResponseEntity.ok(authenticationService.signup(request));
        }
        catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(authenticationService.login(request));
    }
}
