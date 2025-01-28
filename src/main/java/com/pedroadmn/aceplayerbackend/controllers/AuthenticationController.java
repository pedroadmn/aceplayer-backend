package com.pedroadmn.aceplayerbackend.controllers;

import com.pedroadmn.aceplayerbackend.auth.AuthenticationResponse;
import com.pedroadmn.aceplayerbackend.auth.AuthenticationService;
import com.pedroadmn.aceplayerbackend.auth.AuthenticationRequest;
import com.pedroadmn.aceplayerbackend.auth.RegistrationRequest;
import com.pedroadmn.aceplayerbackend.repositories.user.UserRepository;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.mail.MessagingException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("auth")
@RequiredArgsConstructor
@Tag(name = "Authentication")
public class AuthenticationController {
    private final UserRepository userRepository;
    private final AuthenticationService authenticationService;

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody @Valid AuthenticationRequest request) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public ResponseEntity<?> register(@RequestBody @Valid RegistrationRequest request) throws MessagingException {
        if(this.userRepository.findByEmail(request.getEmail()).isPresent()) {
            return ResponseEntity.badRequest().build();
        }
//        return ResponseEntity.ok(authenticationService.register(request));
        authenticationService.register(request);
        return ResponseEntity.accepted().build();
    }



//    @PostMapping("/refresh-token")
//    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
//        authenticationService.refreshToken(request, response);
//    }
}
