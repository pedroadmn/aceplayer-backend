package com.pedroadmn.aceplayerbackend.repositories.role;

import com.pedroadmn.aceplayerbackend.domain.role.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Integer> {

    Optional<Role> findByName(String role);
}
