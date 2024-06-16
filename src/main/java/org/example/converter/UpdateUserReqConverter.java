package org.example.converter;

import org.example.api.request.UpdateUserReq;
import org.example.entity.User;
import org.mapstruct.Mapper;
import org.mapstruct.MappingConstants;
import org.mapstruct.MappingTarget;
import org.mapstruct.ReportingPolicy;

@Mapper(componentModel = MappingConstants.ComponentModel.SPRING,
  unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface UpdateUserReqConverter {

    void setInfo(@MappingTarget User target, UpdateUserReq source);

}
