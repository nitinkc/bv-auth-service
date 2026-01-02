package com.bitvelocity.auth.service;

import com.bit.velocity.common.security.UserContext;
import com.bit.velocity.common.security.jwt.JwtTokenService;
import com.bitvelocity.auth.domain.AccountStatus;
import com.bitvelocity.auth.domain.RefreshToken;
import com.bitvelocity.auth.domain.Role;
import com.bitvelocity.auth.domain.User;
import com.bitvelocity.auth.dto.AuthResponse;
import com.bitvelocity.auth.dto.LoginRequest;
import com.bitvelocity.auth.dto.RefreshTokenRequest;
import com.bitvelocity.auth.dto.RegisterRequest;
import com.bitvelocity.auth.exception.AccountLockedException;
import com.bitvelocity.auth.exception.InvalidTokenException;
import com.bitvelocity.auth.exception.UserAlreadyExistsException;
import com.bitvelocity.auth.repository.RefreshTokenRepository;
import com.bitvelocity.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthenticationService Unit Tests")
class AuthenticationServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtTokenService jwtTokenService;

    @Mock
    private AuthenticationManager authenticationManager;

    @InjectMocks
    private AuthenticationService authenticationService;

    private RegisterRequest registerRequest;
    private LoginRequest loginRequest;
    private User testUser;

    @BeforeEach
    void setUp() {
        // Set up service configuration
        ReflectionTestUtils.setField(authenticationService, "accountLockoutEnabled", true);
        ReflectionTestUtils.setField(authenticationService, "maxFailedAttempts", 5);
        ReflectionTestUtils.setField(authenticationService, "lockoutDurationMinutes", 30);
        ReflectionTestUtils.setField(authenticationService, "refreshTokenExpiration", 604800000L);

        // Create test data
        registerRequest = new RegisterRequest();
        registerRequest.setUsername("testuser");
        registerRequest.setEmail("test@example.com");
        registerRequest.setPassword("TestPass123!");

        loginRequest = new LoginRequest();
        loginRequest.setUsername("testuser");
        loginRequest.setPassword("TestPass123!");

        testUser = User.builder()
                .id(UUID.randomUUID())
                .username("testuser")
                .email("test@example.com")
                .password("$2a$10$hashedPassword")
                .roles(Set.of(Role.ROLE_USER))
                .status(AccountStatus.ACTIVE)
                .failedLoginAttempts(0)
                .build();
    }

    // ==================== REGISTRATION TESTS ====================

    @Test
    @DisplayName("Should successfully register a new user")
    void testRegister_Success() {
        // Given
        when(userRepository.existsByUsername(anyString())).thenReturn(false);
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(passwordEncoder.encode(anyString())).thenReturn("$2a$10$hashedPassword");
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        when(jwtTokenService.generateAccessToken(any(UserContext.class))).thenReturn("access-token");
        when(jwtTokenService.generateRefreshToken(any(UserContext.class))).thenReturn("refresh-token");
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(new RefreshToken());

        // When
        AuthResponse response = authenticationService.register(registerRequest);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getAccessToken()).isEqualTo("access-token");
        assertThat(response.getRefreshToken()).isEqualTo("refresh-token");
        assertThat(response.getTokenType()).isEqualTo("Bearer");
        assertThat(response.getUser().getUsername()).isEqualTo("testuser");
        assertThat(response.getUser().getRoles()).contains("ROLE_USER");

        // Verify interactions
        verify(userRepository).existsByUsername("testuser");
        verify(userRepository).existsByEmail("test@example.com");
        verify(passwordEncoder).encode("TestPass123!");
        verify(userRepository).save(any(User.class));
        verify(jwtTokenService).generateAccessToken(any(UserContext.class));
        verify(jwtTokenService).generateRefreshToken(any(UserContext.class));
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("Should throw exception when username already exists")
    void testRegister_UsernameExists() {
        // Given
        when(userRepository.existsByUsername(anyString())).thenReturn(true);

        // When & Then
        assertThatThrownBy(() -> authenticationService.register(registerRequest))
                .isInstanceOf(UserAlreadyExistsException.class)
                .hasMessageContaining("Username already exists");

        verify(userRepository).existsByUsername("testuser");
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should throw exception when email already exists")
    void testRegister_EmailExists() {
        // Given
        when(userRepository.existsByUsername(anyString())).thenReturn(false);
        when(userRepository.existsByEmail(anyString())).thenReturn(true);

        // When & Then
        assertThatThrownBy(() -> authenticationService.register(registerRequest))
                .isInstanceOf(UserAlreadyExistsException.class)
                .hasMessageContaining("Email already exists");

        verify(userRepository).existsByEmail("test@example.com");
        verify(userRepository, never()).save(any(User.class));
    }

    // ==================== LOGIN TESTS ====================

    @Test
    @DisplayName("Should successfully login with valid credentials")
    void testLogin_Success() {
        // Given
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(testUser));
        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenReturn(new UsernamePasswordAuthenticationToken(testUser, null, testUser.getAuthorities()));
        when(jwtTokenService.generateAccessToken(any(UserContext.class))).thenReturn("access-token");
        when(jwtTokenService.generateRefreshToken(any(UserContext.class))).thenReturn("refresh-token");
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(new RefreshToken());

        // When
        AuthResponse response = authenticationService.login(loginRequest);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getAccessToken()).isEqualTo("access-token");
        assertThat(response.getRefreshToken()).isEqualTo("refresh-token");
        assertThat(response.getUser().getUsername()).isEqualTo("testuser");

        // Verify failed attempts were reset
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository, atLeastOnce()).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        assertThat(savedUser.getFailedLoginAttempts()).isEqualTo(0);
        assertThat(savedUser.getLastLogin()).isNotNull();
    }

    @Test
    @DisplayName("Should throw exception when user not found")
    void testLogin_UserNotFound() {
        // Given
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> authenticationService.login(loginRequest))
                .isInstanceOf(org.springframework.security.core.userdetails.UsernameNotFoundException.class)
                .hasMessageContaining("User not found");

        verify(authenticationManager, never()).authenticate(any());
    }

    @Test
    @DisplayName("Should increment failed attempts on bad credentials")
    void testLogin_BadCredentials() {
        // Given
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(testUser));
        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        // When & Then
        assertThatThrownBy(() -> authenticationService.login(loginRequest))
                .isInstanceOf(BadCredentialsException.class);

        // Verify failed attempts incremented
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        assertThat(userCaptor.getValue().getFailedLoginAttempts()).isEqualTo(1);
    }

    @Test
    @DisplayName("Should lock account after max failed attempts")
    void testLogin_AccountLocked() {
        // Given
        testUser.setFailedLoginAttempts(4); // One more attempt will lock
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(testUser));
        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        // When & Then
        assertThatThrownBy(() -> authenticationService.login(loginRequest))
                .isInstanceOf(BadCredentialsException.class);

        // Verify account locked
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        assertThat(savedUser.getFailedLoginAttempts()).isEqualTo(5);
        assertThat(savedUser.getLockedUntil()).isNotNull();
    }

    @Test
    @DisplayName("Should throw exception when account is locked")
    void testLogin_AccountCurrentlyLocked() {
        // Given
        testUser.setStatus(AccountStatus.LOCKED); // Must set status to LOCKED
        testUser.setLockedUntil(LocalDateTime.now().plusMinutes(30));
        testUser.setFailedLoginAttempts(5);
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(testUser));

        // When & Then
        assertThatThrownBy(() -> authenticationService.login(loginRequest))
                .isInstanceOf(AccountLockedException.class)
                .hasMessageContaining("locked");

        verify(authenticationManager, never()).authenticate(any());
    }

    @Test
    @DisplayName("Should unlock account after lockout period expires")
    void testLogin_AccountUnlockedAfterTimeout() {
        // Given
        testUser.setLockedUntil(LocalDateTime.now().minusMinutes(1)); // Expired
        testUser.setFailedLoginAttempts(5);
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(testUser));
        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenReturn(new UsernamePasswordAuthenticationToken(testUser, null, testUser.getAuthorities()));
        when(jwtTokenService.generateAccessToken(any(UserContext.class))).thenReturn("access-token");
        when(jwtTokenService.generateRefreshToken(any(UserContext.class))).thenReturn("refresh-token");
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(new RefreshToken());

        // When
        AuthResponse response = authenticationService.login(loginRequest);

        // Then
        assertThat(response).isNotNull();

        // Verify account unlocked
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository, atLeastOnce()).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        assertThat(savedUser.getFailedLoginAttempts()).isEqualTo(0);
        assertThat(savedUser.getLockedUntil()).isNull();
    }

    // ==================== REFRESH TOKEN TESTS ====================

    @Test
    @DisplayName("Should successfully refresh access token")
    void testRefreshToken_Success() {
        // Given
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("valid-refresh-token");

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken("valid-refresh-token");
        refreshToken.setUser(testUser);
        refreshToken.setExpiresAt(LocalDateTime.now().plusDays(7));
        refreshToken.setRevoked(false);

        when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(refreshToken));
        when(jwtTokenService.generateAccessToken(any(UserContext.class))).thenReturn("new-access-token");

        // When
        AuthResponse response = authenticationService.refreshToken(request);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getAccessToken()).isEqualTo("new-access-token");
        assertThat(response.getRefreshToken()).isEqualTo("valid-refresh-token");
        assertThat(response.getUser().getUsername()).isEqualTo("testuser");

        verify(refreshTokenRepository).findByToken("valid-refresh-token");
        verify(jwtTokenService).generateAccessToken(any(UserContext.class));
    }

    @Test
    @DisplayName("Should throw exception when refresh token not found")
    void testRefreshToken_NotFound() {
        // Given
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("invalid-token");

        when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> authenticationService.refreshToken(request))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("Invalid refresh token");

        verify(jwtTokenService, never()).generateAccessToken(any(UserContext.class));
    }

    @Test
    @DisplayName("Should throw exception when refresh token is expired")
    void testRefreshToken_Expired() {
        // Given
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("expired-token");

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken("expired-token");
        refreshToken.setUser(testUser);
        refreshToken.setExpiresAt(LocalDateTime.now().minusDays(1)); // Expired
        refreshToken.setRevoked(false);

        when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(refreshToken));

        // When & Then
        assertThatThrownBy(() -> authenticationService.refreshToken(request))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("expired");

        verify(jwtTokenService, never()).generateAccessToken(any(UserContext.class));
    }

    @Test
    @DisplayName("Should throw exception when refresh token is revoked")
    void testRefreshToken_Revoked() {
        // Given
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("revoked-token");

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken("revoked-token");
        refreshToken.setUser(testUser);
        refreshToken.setExpiresAt(LocalDateTime.now().plusDays(7));
        refreshToken.setRevoked(true); // Revoked

        when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(refreshToken));

        // When & Then
        assertThatThrownBy(() -> authenticationService.refreshToken(request))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("revoked");

        verify(jwtTokenService, never()).generateAccessToken(any(UserContext.class));
    }

    // ==================== LOGOUT TESTS ====================

    @Test
    @DisplayName("Should successfully logout user")
    void testLogout_Success() {
        // Given
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(testUser));

        // When
        authenticationService.logout("testuser");

        // Then
        verify(refreshTokenRepository).revokeAllUserTokens(testUser);
    }

    @Test
    @DisplayName("Should throw exception when user not found during logout")
    void testLogout_UserNotFound() {
        // Given
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> authenticationService.logout("testuser"))
                .isInstanceOf(org.springframework.security.core.userdetails.UsernameNotFoundException.class);

        verify(refreshTokenRepository, never()).revokeAllUserTokens(any());
    }

    // ==================== GET CURRENT USER TESTS ====================

    @Test
    @DisplayName("Should get current user successfully")
    void testGetCurrentUser_Success() {
        // Given
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(testUser));

        // When
        var response = authenticationService.getCurrentUser("testuser");

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getUsername()).isEqualTo("testuser");
        assertThat(response.getEmail()).isEqualTo("test@example.com");
        assertThat(response.getRoles()).contains("ROLE_USER");
        assertThat(response.getStatus()).isEqualTo("ACTIVE");

        verify(userRepository).findByUsername("testuser");
    }

    @Test
    @DisplayName("Should throw exception when user not found")
    void testGetCurrentUser_NotFound() {
        // Given
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> authenticationService.getCurrentUser("testuser"))
                .isInstanceOf(org.springframework.security.core.userdetails.UsernameNotFoundException.class);
    }
}
