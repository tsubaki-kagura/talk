package org.kagura.model;

import jakarta.persistence.*;
import lombok.*;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Getter
@Setter
@ToString
@EqualsAndHashCode(onlyExplicitlyIncluded = true, callSuper = false)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "users")
public class UserModel extends BaseModel implements UserDetails {

    public UserModel(String username, String password) {
        this.username = username;
        this.password = password;
    }

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "users_seq")
    @SequenceGenerator(name = "users_seq", sequenceName = "users_uid_seq")
    @EqualsAndHashCode.Include
    private Long uid;

    @Column(name = "uname", unique = true, nullable = false, length = 32)
    private String username;

    @Column(name = "passwd", nullable = false, length = 64)
    private String password;

    @Override
    public @NonNull Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(() -> "ROLE_USER");
    }

    public Map<String, Object> createJwtPayload() {
        return new HashMap<>(
                Map.of(
                        "uid", uid,
                        "uname", username
                )
        );
    }
}
