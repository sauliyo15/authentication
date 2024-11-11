package com.sauliyo15.autenticacion.controller;

import com.sauliyo15.autenticacion.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/test")
public class TestController {

    @Autowired
    UserRepository userRepository;

    @GetMapping("/noAuth")
    public String noAuth() {
        return "Everyone can see this";
    }

    @GetMapping("/allUsers")
    public ResponseEntity<?> allUsers() {
        return ResponseEntity.ok(userRepository.findAll());
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('CLIENT')")
    public String users() {
        return "Only users can see this";
    }

    @GetMapping("/admins")
    @PreAuthorize("hasRole('ADMIN')")
    public String admins() {
        return "Only admins can see this";
    }

    @GetMapping("/roles")
    @PreAuthorize("hasAnyRole('CLIENT', 'ADMIN')")
    public String roles() {
        return "Users and admins can see this";
    }
}
