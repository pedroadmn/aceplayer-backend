package com.pedroadmn.aceplayerbackend.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("status")
@RequiredArgsConstructor
public class StatusController {

    @GetMapping("")
    public ResponseEntity<?> getStatus() {
        return ResponseEntity.ok(Map.of("key", "status response"));
    }
}
