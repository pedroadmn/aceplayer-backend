package com.pedroadmn.aceplayerbackend.domain.user;

public record RegisterDTO(String login, String password, UserRole role) {
}
