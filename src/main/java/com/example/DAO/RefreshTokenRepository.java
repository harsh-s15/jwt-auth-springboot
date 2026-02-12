package com.example.DAO;

import com.example.bean.RefreshToken;
import java.util.Optional;

public interface RefreshTokenRepository {

    void save(RefreshToken token);

    Optional<RefreshToken> findByToken(String token);

    void delete(String token);
}
