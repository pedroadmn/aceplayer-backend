package com.pedroadmn.aceplayerbackend.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.sql.DataSource;
import java.sql.*;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("status")
@RequiredArgsConstructor
public class StatusController {

    private final DataSource dataSource;

    @GetMapping("")
    public ResponseEntity<Map<String, Object>> getStatus() {
        Map<String, Object> status = new HashMap<>();
        Map<String, Object> dependencies = new HashMap<>();
        Map<String, Object> database = new HashMap<>();
        String updatedAt = Instant.now().toString();

        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement()) {

            ResultSet rs = statement.executeQuery("SHOW server_version;");
            if (rs.next()) {
                database.put("version", rs.getString("server_version"));
            }

            rs = statement.executeQuery("SHOW max_connections;");
            if (rs.next()) {
                database.put("max_connections", Integer.parseInt(rs.getString("max_connections")));
            }

            String databaseName = connection.getCatalog();
            System.out.println(databaseName);
            PreparedStatement preparedStatement = connection.prepareStatement(
                    "SELECT count(*)::int FROM pg_stat_activity WHERE datname = ?;");
            preparedStatement.setString(1, databaseName);
            rs = preparedStatement.executeQuery();

            if (rs.next()) {
                database.put("opened_connections", rs.getInt(1));
            }

        } catch (SQLException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Error when try to get the database status", "details", e.getMessage()));
        }

        dependencies.put("database", database);
        status.put("updated_at", updatedAt);
        status.put("dependencies", dependencies);

        return ResponseEntity.ok(status);
    }
}
