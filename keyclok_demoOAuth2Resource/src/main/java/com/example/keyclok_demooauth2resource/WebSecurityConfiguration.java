package com.example.keyclok_demooauth2resource;


import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    public final OAuth2ResourceServerProperties properties;

    @Autowired
    public WebSecurityConfiguration(OAuth2ResourceServerProperties properties) {
        this.properties = properties;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorizeRequests -> authorizeRequests
                        .antMatchers("/test/anonymous").permitAll()
                        .antMatchers("/test/user").hasRole("APP_USER")
                        .anyRequest().authenticated())

                .oauth2ResourceServer(resourceServerConfigurer -> resourceServerConfigurer
                        .jwt(jwtConfigurer -> jwtConfigurer
                                .decoder(jwtDecoder(properties))
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                        ));
    }

    @Bean
    public JwtDecoder jwtDecoder(OAuth2ResourceServerProperties properties) {
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(properties.getJwt().getJwkSetUri())
                .build();
        jwtDecoder.setJwtValidator(buildDelegatingOAuth2TokenValidator());
        jwtDecoder.setClaimSetConverter(buildMappedJwtClaimSetConverter());
        return jwtDecoder;
    }

    private DelegatingOAuth2TokenValidator<Jwt> buildDelegatingOAuth2TokenValidator() {
        List<OAuth2TokenValidator<Jwt>> oAuth2TokenValidators = new ArrayList<>();
        // oAuth2TokenValidators.add(new JwtClaimValidator<List<String>>(AUD, aud -> aud.contains("messaging")));
        oAuth2TokenValidators.add(jwt -> {
            System.out.println(jwt.getClaims());
            //тут можно писать свою кастомуню валидацию
            return OAuth2TokenValidatorResult.success();
        });
        oAuth2TokenValidators.add(new JwtTimestampValidator());
        return new DelegatingOAuth2TokenValidator<>(oAuth2TokenValidators);
    }

    private Converter<Map<String, Object>, Map<String, Object>> buildMappedJwtClaimSetConverter() {
        // кастомная конвертация если нужно добавить.
        return MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());
    }

    @Bean
    public Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter());
        return jwtAuthenticationConverter;
    }

    //Вы также можете настроить другой префикс полномочий. Вместо того, чтобы добавлять к каждому авторитету префикс SCOPE_, вы можете изменить его ROLE_так:
    @Bean
    public Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter() {
        JwtGrantedAuthoritiesConverter delegate = new JwtGrantedAuthoritiesConverter();

        return new Converter<>() {
            @Override
            public Collection<GrantedAuthority> convert(Jwt jwt) {
                Collection<GrantedAuthority> grantedAuthorities = delegate.convert(jwt);

                if (jwt.getClaim("realm_access") == null) {
                    return grantedAuthorities;
                }
                JSONObject realmAccess = jwt.getClaim("realm_access");
                if (realmAccess.get("roles") == null) {
                    return grantedAuthorities;
                }
                JSONArray roles = (JSONArray) realmAccess.get("roles");

                final List<SimpleGrantedAuthority> keycloakAuthorities = roles.stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role)).collect(Collectors.toList());
                grantedAuthorities.addAll(keycloakAuthorities);

                return grantedAuthorities;
            }
        };
    }
}
