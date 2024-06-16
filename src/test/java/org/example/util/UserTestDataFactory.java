package org.example.util;

import org.example.entity.User;
import org.example.entity.UserRole;
import org.example.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Service
public class UserTestDataFactory {

    public static final String PASSWORD = "Test12345";

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder bCryptPasswordEncoder;

    public User createUser(String username, String firstName, Collection<UserRole> authorities) {
        User savedEntity = new User();
        savedEntity.setUsername(username);
        savedEntity.setPassword(bCryptPasswordEncoder.encode(PASSWORD));
        savedEntity.setFirstName(firstName);
        savedEntity.setLastName("Tester");
        savedEntity.setEmail(String.format("%s@gmail.com", username));
        savedEntity.setCity("Ho Chi Minh");
        if (authorities.isEmpty()) {
            savedEntity.setAuthorities(Set.of(UserRole.USER));
        } else {
            savedEntity.setAuthorities(new HashSet<>(authorities));
        }
        return userRepository.save(savedEntity);
    }

}
