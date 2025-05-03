package com.janak.Security.service;

import com.janak.Security.model.Users;
import com.janak.Security.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public Users  registerUser(Users user) {
        if (userRepository.existsById(user.getUsername())) {
            throw new RuntimeException("User already exists");
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));

        userRepository.save(user);
        return user;
    }


}
