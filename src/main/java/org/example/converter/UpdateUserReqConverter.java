package org.example.converter;

import org.example.api.request.UpdateUserReq;
import org.example.entity.User;
import org.mapstruct.Mapper;
import org.mapstruct.MappingTarget;

@Mapper(componentModel = "spring")
public interface UpdateUserReqConverter {

    void setInfo(@MappingTarget User target, UpdateUserReq source);

}
