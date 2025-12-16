package com.bit.velocity.authservice.controller;

import com.bit.velocity.authservice.model.User;
import com.bit.velocity.authservice.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    private UserService userService;

    // Placeholder for registration endpoint
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody User user) {
        // Registration logic placeholder
        return ResponseEntity.ok("User registered (placeholder)");
    }

    // Placeholder for login endpoint
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody User user) {
        // Login logic placeholder
        return ResponseEntity.ok("User logged in (placeholder)");
    }
}