package com.pedroadmn.aceplayerbackend.repositories.user;

import com.pedroadmn.aceplayerbackend.domain.user.Token;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {

    Optional<Token> findByToken(String token);
}
