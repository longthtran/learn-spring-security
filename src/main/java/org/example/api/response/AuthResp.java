package org.example.api.response;

public record AuthResp(String message, boolean error, String token) {
}
