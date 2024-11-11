package com.sauliyo15.autenticacion.filter;

import com.sauliyo15.autenticacion.service.impl.JwtService;
import com.sauliyo15.autenticacion.service.impl.UserServiceImpl;
import com.sauliyo15.autenticacion.util.SecurityUtils;
import io.micrometer.common.util.StringUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserServiceImpl userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // Verifica si el encabezado Authorization está presente y contiene el prefijo "Bearer "
        if (StringUtils.isEmpty(authHeader) || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response); // Continuar sin hacer nada si no es un token JWT válido
            return;
        }

        // Extrae el JWT del encabezado "Authorization"
        jwt = authHeader.substring(7); // Bearer XXXX
        log.info("JWT -> {}", jwt);
        userEmail = jwtService.extractUserName(jwt);

        if (!StringUtils.isEmpty(userEmail) && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userService.userDetailsService().loadUserByUsername(userEmail);

            if (jwtService.isTokenValid(jwt, userDetails)) {
                log.debug("User - {}", userDetails);

                // Usamos SecurityUtils para obtener el usuario autenticado
                UserDetails authenticatedUser = SecurityUtils.getAuthenticatedUser();

                if (authenticatedUser == null) {
                    log.warn("Usuario no autenticado.");
                    filterChain.doFilter(request, response);
                    return;
                }

                // Si el JWT es válido, creamos la autenticación
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                context.setAuthentication(authToken);
                SecurityContextHolder.setContext(context);
            }
        }
        // Continúa el procesamiento de la solicitud
        filterChain.doFilter(request, response);
    }
}
