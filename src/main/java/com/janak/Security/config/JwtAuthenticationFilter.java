package com.janak.Security.config;

import com.janak.Security.service.CustomUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService customUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NonNull HttpServletResponse response,@NonNull FilterChain filterChain) throws ServletException, IOException {
        // Bearer {jwtToken}
        String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;

        if(authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            username = jwtUtil.extractUsername(token);
        }

        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
            if (jwtUtil.validateToken(token, userDetails)) {
                // Even though the JWT proves the user is legit, Spring needs to be told about it every time, since it doesn't maintain state across requests.
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails /* Represents the current authenticated user's details */, null /* Represents the credentials. Since the token is already validated, credentials are not needed*/, userDetails.getAuthorities()); // Creates an authentication token representing a logged-in user
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); // Sets the details of the authentication token, such as the remote address and session ID
                SecurityContextHolder.getContext().setAuthentication(authenticationToken); // Sets the authentication token in the security context, making it available for the current request
            }
        }
        filterChain.doFilter(request, response);
    }
}
