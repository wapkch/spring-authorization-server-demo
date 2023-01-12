package io.github.cathy.oauth2.server.authorization.client;

import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;

public class TenantRegisteredClientRepository extends JdbcRegisteredClientRepository {

    /**
     * Constructs a {@code JdbcRegisteredClientRepository} using the provided parameters.
     *
     * @param jdbcOperations the JDBC operations
     */
    public TenantRegisteredClientRepository(JdbcOperations jdbcOperations) {
        super(jdbcOperations);
    }



}
