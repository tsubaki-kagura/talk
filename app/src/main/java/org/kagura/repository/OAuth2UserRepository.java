package org.kagura.repository;

import org.kagura.model.OAuth2UserModel;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OAuth2UserRepository extends JpaRepository<OAuth2UserModel, Long> {
    Optional<OAuth2UserModel> findByProvider(String provider, String providerUserId);
}
