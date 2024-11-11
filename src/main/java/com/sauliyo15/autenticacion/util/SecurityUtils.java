package com.sauliyo15.autenticacion.util;

import com.sauliyo15.autenticacion.entities.UserEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

public class SecurityUtils {

    // Método para obtener el usuario autenticado del contexto de seguridad
    public static UserEntity getAuthenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
            return (UserEntity) authentication.getPrincipal();
        }
        return null;
    }
}
