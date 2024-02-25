package com.startup.viso.oauth2service.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.UUID;
import java.util.stream.Stream;

@Configuration
@EnableWebSecurity
public class VisoOAuthServerConfiguration {

    private PasswordEncoder passwordEncoder;

    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        RegisteredClient registeredClient = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientName("VISO REST Client")
                .clientId("viso_client")
                .clientSecret(passwordEncoder.encode("viso_secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantTypes(types -> {
                    types.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
                    types.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                    types.add(AuthorizationGrantType.REFRESH_TOKEN);})
                .scopes(s -> {
                    s.add("web_client");
                    s.add("viso_read");})
                .redirectUris(uris -> {
                    uris.add("http://127.0.0.1:8901//api/v1/oauth2/token");
                    uris.add("http://127.0.0.1:8901/authorized");
                    uris.add("http://127.0.0.1:8901/login/oauth2/viso-client-oidc");})
                .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Autowired
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

}
