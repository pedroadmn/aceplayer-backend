package com.pedroadmn.aceplayerbackend.domain.user;

public record RegisterDTO(String email, String password, UserRole role) {
}
