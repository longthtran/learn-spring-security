package org.example.entity;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;

@Getter
public enum UserRole implements GrantedAuthority {

    ADMIN,
    MOD,
    USER;

    @Override
    public String getAuthority() {
        return this.name();
    }

}
