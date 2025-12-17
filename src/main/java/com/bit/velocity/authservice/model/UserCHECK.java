package com.bit.velocity.authservice.model;

import com.bit.velocity.common.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.util.Set;

/**
 * User entity for authentication service.
 * Extends BaseEntity for audit tracking as defined in the architecture.
 */
@Entity
@Table(name = "users")
@Data
@EqualsAndHashCode(callSuper = true)
public class UserCHECK extends BaseEntity {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true, nullable = false)
    private String username;
    
    @Column(unique = true, nullable = false)
    private String email;
    
    @Column(nullable = false)
    private String passwordHash;
    
    @Column(nullable = false)
    private Boolean active = true;
    
    @Column
    private String firstName;
    
    @Column
    private String lastName;
    
    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    private Set<Role> roles;
    
    public enum Role {
        USER, ADMIN, PRODUCT_MANAGER, CUSTOMER_SERVICE
    }
}