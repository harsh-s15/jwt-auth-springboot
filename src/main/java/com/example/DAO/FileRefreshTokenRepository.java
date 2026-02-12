package com.example.DAO;

import com.example.bean.RefreshToken;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Repository;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Repository
public class FileRefreshTokenRepository implements RefreshTokenRepository {

    private final Path file = Paths.get("data/refresh_tokens.json");
    private final ObjectMapper mapper = new ObjectMapper();

    private Map<String, RefreshToken> load() {
        try {
            if (!Files.exists(file)) return new HashMap<>();
            if (Files.size(file) == 0) return new HashMap<>();

            return mapper.readValue(
                    Files.readString(file),
                    new TypeReference<Map<String, RefreshToken>>() {}
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void persist(Map<String, RefreshToken> tokens) {
        try {
            Files.createDirectories(file.getParent());
            mapper.writerWithDefaultPrettyPrinter()
                    .writeValue(file.toFile(), tokens);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void save(RefreshToken token) {
        Map<String, RefreshToken> tokens = load();
        tokens.put(token.getToken(), token);
        persist(tokens);
    }

    @Override
    public Optional<RefreshToken> findByToken(String token) {
        return Optional.ofNullable(load().get(token));
    }

    @Override
    public void delete(String token) {
        Map<String, RefreshToken> tokens = load();
        tokens.remove(token);
        persist(tokens);
    }
}
