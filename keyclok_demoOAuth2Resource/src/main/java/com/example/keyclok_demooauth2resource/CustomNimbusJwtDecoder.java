//package com.example.keyclok_demooauth2resource;
//
//import com.nimbusds.jose.JOSEException;
//import com.nimbusds.jose.JWSAlgorithm;
//import com.nimbusds.jose.RemoteKeySourceException;
//import com.nimbusds.jose.jwk.JWKSet;
//import com.nimbusds.jose.jwk.source.JWKSetCache;
//import com.nimbusds.jose.jwk.source.JWKSource;
//import com.nimbusds.jose.jwk.source.RemoteJWKSet;
//import com.nimbusds.jose.proc.JWSKeySelector;
//import com.nimbusds.jose.proc.JWSVerificationKeySelector;
//import com.nimbusds.jose.proc.SecurityContext;
//import com.nimbusds.jose.proc.SingleKeyJWSKeySelector;
//import com.nimbusds.jose.util.Resource;
//import com.nimbusds.jose.util.ResourceRetriever;
//import com.nimbusds.jwt.JWT;
//import com.nimbusds.jwt.JWTClaimsSet;
//import com.nimbusds.jwt.JWTParser;
//import com.nimbusds.jwt.PlainJWT;
//import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
//import com.nimbusds.jwt.proc.DefaultJWTProcessor;
//import com.nimbusds.jwt.proc.JWTProcessor;
//import org.apache.commons.logging.Log;
//import org.apache.commons.logging.LogFactory;
//import org.springframework.cache.Cache;
//import org.springframework.core.convert.converter.Converter;
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.HttpMethod;
//import org.springframework.http.MediaType;
//import org.springframework.http.RequestEntity;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.oauth2.core.OAuth2Error;
//import org.springframework.security.oauth2.core.OAuth2TokenValidator;
//import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
//import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
//import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
//import org.springframework.security.oauth2.jwt.BadJwtException;
//import org.springframework.security.oauth2.jwt.Jwt;
//import org.springframework.security.oauth2.jwt.JwtDecoder;
//import org.springframework.security.oauth2.jwt.JwtException;
//import org.springframework.security.oauth2.jwt.JwtValidationException;
//import org.springframework.security.oauth2.jwt.JwtValidators;
//import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;
//import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
//import org.springframework.util.Assert;
//import org.springframework.util.StringUtils;
//import org.springframework.web.client.RestOperations;
//import org.springframework.web.client.RestTemplate;
//
//import javax.crypto.SecretKey;
//import java.io.IOException;
//import java.net.MalformedURLException;
//import java.net.URL;
//import java.security.interfaces.RSAPublicKey;
//import java.text.ParseException;
//import java.util.Arrays;
//import java.util.Collection;
//import java.util.Collections;
//import java.util.HashSet;
//import java.util.Iterator;
//import java.util.LinkedHashMap;
//import java.util.Map;
//import java.util.Set;
//import java.util.function.Consumer;
//
//public class CustomNimbusJwtDecoder implements JwtDecoder {
//    private final Log logger = LogFactory.getLog(this.getClass());
//    private static final String DECODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to decode the Jwt: %s";
//    private final JWTProcessor<SecurityContext> jwtProcessor;
//    private Converter<Map<String, Object>, Map<String, Object>> claimSetConverter = MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());
//    private OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefault();
//
//    public CustomNimbusJwtDecoder(JWTProcessor<SecurityContext> jwtProcessor) {
//        Assert.notNull(jwtProcessor, "jwtProcessor cannot be null");
//        this.jwtProcessor = jwtProcessor;
//    }
//
//    public void setJwtValidator(OAuth2TokenValidator<Jwt> jwtValidator) {
//        Assert.notNull(jwtValidator, "jwtValidator cannot be null");
//        this.jwtValidator = jwtValidator;
//    }
//
//    public void setClaimSetConverter(Converter<Map<String, Object>, Map<String, Object>> claimSetConverter) {
//        Assert.notNull(claimSetConverter, "claimSetConverter cannot be null");
//        this.claimSetConverter = claimSetConverter;
//    }
//
//    public Jwt decode(String token) throws JwtException {
//        JWT jwt = this.parse(token);
//        if (jwt instanceof PlainJWT) {
//            this.logger.trace("Failed to decode unsigned token");
//            throw new BadJwtException("Unsupported algorithm of " + jwt.getHeader().getAlgorithm());
//        } else {
//            Jwt createdJwt = this.createJwt(token, jwt);
//            return this.validateJwt(createdJwt);
//        }
//    }
//
//    private JWT parse(String token) {
//        try {
//            return JWTParser.parse(token);
//        } catch (Exception var3) {
//            this.logger.trace("Failed to parse token", var3);
//            throw new BadJwtException(String.format("An error occurred while attempting to decode the Jwt: %s", var3.getMessage()), var3);
//        }
//    }
//
//    private Jwt createJwt(String token, JWT parsedJwt) {
//        try {
//            JWTClaimsSet jwtClaimsSet = this.jwtProcessor.process(parsedJwt, (SecurityContext)null);
//            Map<String, Object> headers = new LinkedHashMap(parsedJwt.getHeader().toJSONObject());
//            Map<String, Object> claims = (Map)this.claimSetConverter.convert(jwtClaimsSet.getClaims());
//            return Jwt.withTokenValue(token).headers((h) -> {
//                h.putAll(headers);
//            }).claims((c) -> {
//                c.putAll(claims);
//            }).build();
//        } catch (RemoteKeySourceException var6) {
//            this.logger.trace("Failed to retrieve JWK set", var6);
//            if (var6.getCause() instanceof ParseException) {
//                throw new JwtException(String.format("An error occurred while attempting to decode the Jwt: %s", "Malformed Jwk set"));
//            } else {
//                throw new JwtException(String.format("An error occurred while attempting to decode the Jwt: %s", var6.getMessage()), var6);
//            }
//        } catch (JOSEException var7) {
//            this.logger.trace("Failed to process JWT", var7);
//            throw new JwtException(String.format("An error occurred while attempting to decode the Jwt: %s", var7.getMessage()), var7);
//        } catch (Exception var8) {
//            this.logger.trace("Failed to process JWT", var8);
//            if (var8.getCause() instanceof ParseException) {
//                throw new BadJwtException(String.format("An error occurred while attempting to decode the Jwt: %s", "Malformed payload"));
//            } else {
//                throw new BadJwtException(String.format("An error occurred while attempting to decode the Jwt: %s", var8.getMessage()), var8);
//            }
//        }
//    }
//
//    private Jwt validateJwt(Jwt jwt) {
//        OAuth2TokenValidatorResult result = this.jwtValidator.validate(jwt);
//        if (result.hasErrors()) {
//            Collection<OAuth2Error> errors = result.getErrors();
//            String validationErrorString = this.getJwtValidationExceptionMessage(errors);
//            throw new JwtValidationException(validationErrorString, errors);
//        } else {
//            return jwt;
//        }
//    }
//
//    private String getJwtValidationExceptionMessage(Collection<OAuth2Error> errors) {
//        Iterator var2 = errors.iterator();
//
//        OAuth2Error oAuth2Error;
//        do {
//            if (!var2.hasNext()) {
//                return "Unable to validate Jwt";
//            }
//
//            oAuth2Error = (OAuth2Error)var2.next();
//        } while(StringUtils.isEmpty(oAuth2Error.getDescription()));
//
//        return String.format("An error occurred while attempting to decode the Jwt: %s", oAuth2Error.getDescription());
//    }
//
//
//        private static class CachingResourceRetriever implements ResourceRetriever {
//            private final Cache cache;
//            private final ResourceRetriever resourceRetriever;
//
//            CachingResourceRetriever(Cache cache, ResourceRetriever resourceRetriever) {
//                this.cache = cache;
//                this.resourceRetriever = resourceRetriever;
//            }
//
//            public Resource retrieveResource(URL url) throws IOException {
//                try {
//                    String jwkSet = (String)this.cache.get(url.toString(), () -> {
//                        return this.resourceRetriever.retrieveResource(url).getContent();
//                    });
//                    return new Resource(jwkSet, "UTF-8");
//                } catch (Cache.ValueRetrievalException var4) {
//                    Throwable thrownByValueLoader = var4.getCause();
//                    if (thrownByValueLoader instanceof IOException) {
//                        throw (IOException)thrownByValueLoader;
//                    } else {
//                        throw new IOException(thrownByValueLoader);
//                    }
//                } catch (Exception var5) {
//                    throw new IOException(var5);
//                }
//            }
//        }
//
//        private static class NoOpJwkSetCache implements JWKSetCache {
//            private NoOpJwkSetCache() {
//            }
//
//            public void put(JWKSet jwkSet) {
//            }
//
//            public JWKSet get() {
//                return null;
//            }
//
//            public boolean requiresRefresh() {
//                return true;
//            }
//        }
//    }
//}
