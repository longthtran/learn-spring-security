package org.example.api.response;

public record FindUserResp(String username, String firstName, String lastName, String email,
                           String address, String city, String phone) {
}
