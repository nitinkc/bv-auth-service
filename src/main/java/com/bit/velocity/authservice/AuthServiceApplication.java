package com.bit.velocity.authservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


/**
 * Authentication Service for BitVelocity eCommerce domain.
 *
 * Implements secure authentication with JWT tokens, user management,
 * and role-based access control as defined in EPIC-002.
 *
 * Key Features:
 * - JWT token generation and validation
 * - User registration and login
 * - Password security with bcrypt
 * - Role-based access control (RBAC)
 * - Rate limiting for security
 */
@SpringBootApplication
public class AuthServiceApplication {
  public static void main(String[] args) {
    SpringApplication.run(AuthServiceApplication.class, args);
  }
}

