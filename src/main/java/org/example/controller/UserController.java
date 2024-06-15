package org.example.controller;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.example.api.request.CreateUserReq;
import org.example.api.response.CreateUserResp;
import org.example.converter.UserConverter;
import org.example.entity.User;
import org.example.service.UserService;
import org.example.service.security.JwtTokenProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
@Slf4j
public class UserController {

    private final UserService userService;

    private final JwtTokenProvider jwtTokenProvider;

    private final UserConverter userConverter;

    @PostMapping
    public ResponseEntity<CreateUserResp> create(@Valid @RequestBody CreateUserReq request, BindingResult result) {
        log.info("Receive create user request: {}", request);
        if (result.hasErrors()) {
            return ResponseEntity.badRequest().body(new CreateUserResp("Please check the payload", null));
        } else if (!StringUtils.equals(request.password(), request.rePassword())) {
            return ResponseEntity.badRequest().body(new CreateUserResp("Please check submitted password", null));
        }

        User entity = userConverter.toEntity(request);
        try {
            User savedEntity = userService.save(entity);
            log.debug("Create user {} successfully", savedEntity.getUsername());

            String token = jwtTokenProvider.generateToken(savedEntity.getUsername(), savedEntity.getAuthorities());
            log.debug("Generate token for user {} - token {}", savedEntity.getUsername(), token);

            return ResponseEntity.status(HttpStatus.CREATED).body(new CreateUserResp("Create user successfully", token));
        } catch (Exception e) {
            log.error("Error create user: {}", e.getMessage());
        }
        return ResponseEntity.unprocessableEntity().body(new CreateUserResp("The username already existed", null));
    }
    
}