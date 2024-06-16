package org.example.converter;

import org.apache.commons.lang3.StringUtils;
import org.example.api.request.CreateUserReq;
import org.example.api.response.FindUserResp;
import org.example.entity.User;
import org.example.entity.UserRole;
import org.mapstruct.AfterMapping;
import org.mapstruct.BeforeMapping;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingConstants;
import org.mapstruct.MappingTarget;
import org.mapstruct.ReportingPolicy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.CollectionUtils;

import java.util.Set;

@Mapper(componentModel = MappingConstants.ComponentModel.SPRING,
  unmappedTargetPolicy = ReportingPolicy.IGNORE)
public abstract class UserConverter {

    @Autowired
    protected PasswordEncoder bCryptPasswordEncoder;

    public abstract User toEntity(CreateUserReq dto);

    public abstract FindUserResp toDto(User entity);

    @BeforeMapping
    void setBCryptPasswordEncoder(@MappingTarget User user, CreateUserReq request) {
        String rawPwd = request.password();
        if (StringUtils.isNotBlank(rawPwd)) {
            user.setPassword(bCryptPasswordEncoder.encode(rawPwd));
        }
    }

    @AfterMapping
    void setUserRole(@MappingTarget User user) {
        if (CollectionUtils.isEmpty(user.getAuthorities())) {
            user.setAuthorities(Set.of(UserRole.USER));
        }
    }

}
