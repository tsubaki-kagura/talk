package org.kagura.model;

import jakarta.persistence.*;
import lombok.*;

@Getter
@Setter
@ToString
@EqualsAndHashCode(onlyExplicitlyIncluded = true, callSuper = false)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(
        name = "oauth2_users",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "oauth2_users_k1",
                        columnNames = { "provider", "provider_user_id" }
                )
        }
)
public class OAuth2UserModel extends BaseModel {

    public OAuth2UserModel(String provider, String providerUserId, UserModel user) {
        this.provider = provider;
        this.providerUserId = providerUserId;
        this.user = user;
    }

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "oauth2_users_seq")
    @SequenceGenerator(name = "oauth2_users_seq", sequenceName = "oauth2_users_id_seq")
    @EqualsAndHashCode.Include
    private Long id;

    @Column(nullable = false, length = 16)
    private String provider;

    @Column(nullable = false, length = 32)
    private String providerUserId;

    @ToString.Exclude
    @ManyToOne(fetch = FetchType.LAZY, optional = false, cascade = { CascadeType.PERSIST, CascadeType.MERGE })
    @JoinColumn(name = "uid", nullable = false)
    private UserModel user;
}
