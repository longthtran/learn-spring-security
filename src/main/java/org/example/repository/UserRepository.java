package org.example.repository;

import org.example.entity.User;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
public interface UserRepository extends CrudRepository<User, Long> {
    Optional<User> findByUsername(String username);

//    @Transactional
//    @Modifying
    @Query("UPDATE User u SET u.firstName = :#{#user.firstName}, u.lastName = :#{#user.lastName}, " +
      "u.address = :#{#user.address}, u.city= :#{#user.city}, u.phone= :#{#user.phone} WHERE u.username = :#{#user.username}")
    int updateInfo(@Param("user") User user);

//    @Transactional
//    @Modifying
    @Query("UPDATE User u SET u.enabled = true WHERE u.username = :username")
    int enable(@Param("username") String username);

//    @Transactional
//    @Modifying
    @Query("UPDATE User u SET u.enabled = false WHERE u.username = :username")
    int softDelete(@Param("username") String username);
}
