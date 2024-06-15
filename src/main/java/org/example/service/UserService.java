package org.example.service;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.example.api.request.UpdateUserReq;
import org.example.entity.User;
import org.example.entity.UserRole;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.Set;

public interface UserService extends UserDetailsService {

    User get(@NotBlank String username);
    User save(@NotNull User user);
    User update(@NotBlank String username, @NotNull UpdateUserReq updateInfo);
    int enable(@NotBlank String username);
    int softDelete(@NotBlank String username, Set<UserRole> triggerAuthorities);

}
