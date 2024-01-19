package com.pedroadmn.aceplayerbackend.auth;

import com.pedroadmn.aceplayerbackend.domain.user.UserRole;
import lombok.Builder;

@Builder
public record RegisterRequest(String firstName, String lastName, String email, String password, UserRole role) {
}
