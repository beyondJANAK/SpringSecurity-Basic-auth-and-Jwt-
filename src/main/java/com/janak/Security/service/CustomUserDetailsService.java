package com.janak.Security.service;

import com.janak.Security.model.Users;
import com.janak.Security.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users user = userRepository.findById(username).orElseThrow(() -> new UsernameNotFoundException("User not found."));

        return new User(user.getUsername(), user.getPassword(), user.isEnabled(), true, true, true, user.getRole().stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role.name())).toList());
    }
}
