package com.pedroadmn.aceplayerbackend.controllers;

import com.pedroadmn.aceplayerbackend.auth.AuthenticationResponse;
import com.pedroadmn.aceplayerbackend.auth.AuthenticationService;
import com.pedroadmn.aceplayerbackend.auth.AuthenticationRequest;
import com.pedroadmn.aceplayerbackend.auth.RegisterRequest;
import com.pedroadmn.aceplayerbackend.domain.user.User;
import com.pedroadmn.aceplayerbackend.infra.security.JwtService;
import com.pedroadmn.aceplayerbackend.repositories.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final UserRepository repository;
    private final AuthenticationService authenticationService;

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody @Valid AuthenticationRequest request) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody @Valid RegisterRequest request) {
        if(this.repository.findByEmail(request.email()).isPresent()) return ResponseEntity.badRequest().build();
        return ResponseEntity.ok(authenticationService.register(request));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        authenticationService.refreshToken(request, response);
    }
}
