package com.pedroadmn.aceplayerbackend.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, String> {
    @Query("""
        select t from tokens t inner join users u on t.user.id = u.id
        where u.id = :userId and (t.expired = false or t.revoked = false)
""")
    List<Token> findAllValidTokensByUser(String userId);

    Optional<Token> findByToken(String token);
}
