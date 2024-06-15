package org.example.api.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record CreateUserReq(
  @NotBlank @Email String email,
  @NotBlank @Size(min = 3, message = "The username cant be less than 3 characters")
  @Pattern(regexp = "^[A-Za-z0-9]+", message = "The username can only contains alphabetical and digit characters")
  String username,

  @NotBlank @Size(min = 5, message = "The password cant be less than 5 characters")
  String password,

  @NotBlank @Size(min = 5, message = "The password cant be less than 5 characters")
  String rePassword,

  @NotBlank String firstName,

  @NotBlank
  String lastName,

  String address,

  @NotBlank String city,

  @NotBlank String phone


) {
}
