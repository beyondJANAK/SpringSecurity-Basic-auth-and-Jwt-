package com.janak.Security.service;

import com.janak.Security.config.JwtUtil;
import com.janak.Security.model.Users;
import com.janak.Security.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public String  registerUser(Users user) {
        if (userRepository.existsById(user.getUsername())) {
            throw new RuntimeException("User already exists");
        }

        String token = jwtUtil.generateToken(new User(user.getUsername(), user.getPassword(), user.isEnabled(), true, true, true, user.getRole().stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role.name())).toList()));

        user.setPassword(passwordEncoder.encode(user.getPassword()));

        userRepository.save(user);
        return token;
    }


}
