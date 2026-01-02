package com.bitvelocity.auth.service;

import com.bitvelocity.auth.domain.RefreshToken;
import com.bitvelocity.auth.domain.Role;
import com.bitvelocity.auth.domain.User;
import com.bitvelocity.auth.dto.*;
import com.bitvelocity.auth.exception.AccountLockedException;
import com.bitvelocity.auth.exception.InvalidTokenException;
import com.bitvelocity.auth.exception.UserAlreadyExistsException;
import com.bitvelocity.auth.repository.RefreshTokenRepository;
import com.bitvelocity.auth.repository.UserRepository;
import com.bit.velocity.common.security.jwt.JwtTokenService;
import com.bit.velocity.common.security.UserContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenService jwtTokenService;
    private final AuthenticationManager authenticationManager;

    @Value("${security.account-lockout.enabled:true}")
    private boolean accountLockoutEnabled;

    @Value("${security.account-lockout.max-failed-attempts:5}")
    private int maxFailedAttempts;

    @Value("${security.account-lockout.lockout-duration-minutes:30}")
    private int lockoutDurationMinutes;

    @Value("${jwt.refresh-token-expiration:604800000}")
    private long refreshTokenExpiration;

    /**
     * Register a new user
     */
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        log.info("Registering new user: {}", request.getUsername());

        // Check if username exists
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new UserAlreadyExistsException("Username already exists: " + request.getUsername());
        }

        // Check if email exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException("Email already exists: " + request.getEmail());
        }

        // Create new user
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(Set.of(Role.ROLE_USER)) // Default role
                .build();

        user = userRepository.save(user);
        log.info("User registered successfully: {}", user.getUsername());

        // Generate tokens
        return generateAuthResponse(user);
    }

    /**
     * Authenticate user and generate tokens
     */
    @Transactional
    public AuthResponse login(LoginRequest request) {
        log.info("Login attempt for user: {}", request.getUsername());

        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + request.getUsername()));

        // Check if account is locked
        if (!user.isAccountNonLocked()) {
            if (user.getLockedUntil() != null && LocalDateTime.now().isAfter(user.getLockedUntil())) {
                // Unlock account
                user.resetFailedAttempts();
                userRepository.save(user);
            } else {
                throw new AccountLockedException("Account is locked until: " + user.getLockedUntil());
            }
        }

        try {
            // Authenticate
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            // Reset failed attempts on successful login
            if (user.getFailedLoginAttempts() > 0) {
                user.resetFailedAttempts();
            }

            // Update last login
            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);

            log.info("User logged in successfully: {}", request.getUsername());
            return generateAuthResponse(user);

        } catch (BadCredentialsException e) {
            // Handle failed login attempt
            handleFailedLoginAttempt(user);
            throw new BadCredentialsException("Invalid credentials");
        }
    }

    /**
     * Refresh access token using refresh token
     */
    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        log.info("Refresh token request");

        RefreshToken refreshToken = refreshTokenRepository.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));

        if (!refreshToken.isValid()) {
            throw new InvalidTokenException("Refresh token is expired or revoked");
        }

        User user = refreshToken.getUser();
        
        // Create UserContext for JWT generation
        UserContext userContext = new UserContext();
        userContext.setUserId(user.getId().toString());
        userContext.setUsername(user.getUsername());
        userContext.setEmail(user.getEmail());
        userContext.setRoles(user.getRoles().stream().map(Enum::name).collect(Collectors.toSet()));
        
        // Generate new access token
        String newAccessToken = jwtTokenService.generateAccessToken(userContext);

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshToken.getToken())
                .tokenType("Bearer")
                .expiresIn(900L) // 15 minutes in seconds
                .user(mapToUserInfo(user))
                .build();
    }

    /**
     * Logout user (revoke refresh tokens)
     */
    @Transactional
    public void logout(String username) {
        log.info("Logout request for user: {}", username);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        refreshTokenRepository.revokeAllUserTokens(user);
        log.info("User logged out successfully: {}", username);
    }

    /**
     * Get current user information
     */
    public UserResponse getCurrentUser(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(user.getRoles().stream().map(Enum::name).collect(Collectors.toSet()))
                .status(user.getStatus().name())
                .build();
    }

    /**
     * Generate authentication response with tokens
     */
    private AuthResponse generateAuthResponse(User user) {
        // Create UserContext for JWT generation
        UserContext userContext = new UserContext();
        userContext.setUserId(user.getId().toString());
        userContext.setUsername(user.getUsername());
        userContext.setEmail(user.getEmail());
        userContext.setRoles(user.getRoles().stream().map(Enum::name).collect(Collectors.toSet()));

        // Generate access token
        String accessToken = jwtTokenService.generateAccessToken(userContext);

        // Generate refresh token
        String refreshTokenValue = jwtTokenService.generateRefreshToken(userContext);

        // Store refresh token (refreshTokenExpiration is in milliseconds)
        RefreshToken refreshToken = RefreshToken.builder()
                .token(refreshTokenValue)
                .user(user)
                .expiresAt(LocalDateTime.now().plusSeconds(refreshTokenExpiration / 1000))
                .build();
        refreshTokenRepository.save(refreshToken);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshTokenValue)
                .tokenType("Bearer")
                .expiresIn(900L) // 15 minutes in seconds
                .user(mapToUserInfo(user))
                .build();
    }

    /**
     * Handle failed login attempt
     */
    private void handleFailedLoginAttempt(User user) {
        if (!accountLockoutEnabled) {
            return;
        }

        user.incrementFailedAttempts();

        if (user.getFailedLoginAttempts() >= maxFailedAttempts) {
            user.lockAccount(lockoutDurationMinutes);
            log.warn("Account locked for user: {}", user.getUsername());
        }

        userRepository.save(user);
    }

    /**
     * Map User to UserInfo DTO
     */
    private AuthResponse.UserInfo mapToUserInfo(User user) {
        return AuthResponse.UserInfo.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(user.getRoles().stream().map(Enum::name).collect(Collectors.toSet()))
                .status(user.getStatus().name())
                .lastLogin(user.getLastLogin())
                .build();
    }
}
