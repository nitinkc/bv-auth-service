package com.bit.velocity.authservice.controller;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class TokenController {

    // For Sprint 1 ONLY. Replace with Vault-managed key + RS256 later.
    private final SecretKey key = Keys.hmacShaKeyFor(
            Base64.getDecoder().decode("dGhpc0lzQVRlbXBvcmFyeVNlY3JldEtleUZvckp3dFNwcmluZw=="));

    @PostMapping("/token")
    public ResponseEntity<Map<String,String>> token(@RequestParam String userId) {
        Instant now = Instant.now();
        String jwt = Jwts.builder()
                .setId("jti-" + now.toEpochMilli())
                .setSubject(userId)
                .claim("roles", "CUSTOMER")
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(900)))
                .signWith(key)
                .compact();
        return ResponseEntity.ok(Map.of("access_token", jwt, "token_type", "Bearer", "expires_in", "900"));
    }
}