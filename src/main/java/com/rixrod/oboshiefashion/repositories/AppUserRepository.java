package com.rixrod.oboshiefashion.repositories;

import com.rixrod.oboshiefashion.models.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
@Transactional(readOnly = true)
public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    Optional<AppUser> findByEmail(String Email);

    @Transactional
    @Modifying
    @Query("UPDATE AppUser a SET a.enabled = TRUE WHERE a.email = ?1")
    void enableAppUser(String email);

    @Transactional
    @Modifying
    @Query("UPDATE AppUser a SET a.enabled = FALSE WHERE a.email = ?1")
    void disableAppUser(String email);

    @Transactional
    @Modifying
    @Query("UPDATE AppUser a SET a.locked = TRUE WHERE a.email = ?1")
    void lockAppUser(String email);

    @Transactional
    @Modifying
    @Query("UPDATE AppUser a SET a.locked = FALSE WHERE a.email = ?1")
    void unlockAppUser(String email);
}
