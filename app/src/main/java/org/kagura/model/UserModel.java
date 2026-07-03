package org.kagura.model;

import jakarta.persistence.*;
import lombok.Data;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
@Entity
@Table(name = "users")
public class UserModel implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer uid;

    @Column(name = "uname", unique = true, nullable = false, length = 32)
    private String username;

    @Column(name = "passwd", nullable = false, length = 64)
    private String password;

    @Override
    public @NonNull Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(() -> "USER");
    }
}
