package org.example.service;

import jakarta.validation.ValidationException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.api.request.UpdateUserReq;
import org.example.converter.UpdateUserReqConverter;
import org.example.entity.User;
import org.example.entity.UserRole;
import org.example.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Set;

@Service
@AllArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    private final UpdateUserReqConverter updateUserReqConverter;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User not exist"));
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
          user.getAuthorities());
    }

    @Override
    public User get(String username) {
        return userRepository.findByUsername(username).orElse(null);
    }

    @Override
    public User save(User user) {
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            throw new ValidationException("Username exist!");
        }
        return userRepository.save(user);
    }

    @Override
    public User update(String username, UpdateUserReq updateInfo) {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User not exist"));
        updateUserReqConverter.setInfo(user, updateInfo);
        log.debug("Copy value for user {} - {}", username, user);
        return userRepository.updateInfo(user) == 1 ? user : null;
    }

    @Override
    public int enable(String username) {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User not exist"));
        return userRepository.enable(user.getUsername());
    }

    @Override
    public int softDelete(String username, Set<UserRole> triggerAuthorities) {
        Optional<User> optUser = userRepository.findByUsername(username);
        if (optUser.isEmpty()) {
            return 0;
        }
        User user = optUser.get();
        if (user.getAuthorities().contains(UserRole.ADMIN) ||
          (!triggerAuthorities.contains(UserRole.ADMIN) && user.getAuthorities().contains(UserRole.MOD))) {
            log.warn("Not allow to soft delete user {} because of authorities {}", username, user.getAuthorities());
            return -1;
        }
        return userRepository.softDelete(username);
    }

}
