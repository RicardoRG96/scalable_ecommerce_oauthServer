// package com.ricardo.scalable.ecommerce.platform.oauthServer.security;

// import java.security.KeyPair;
// import java.security.KeyPairGenerator;
// import java.security.interfaces.RSAPrivateKey;
// import java.security.interfaces.RSAPublicKey;
// import java.time.Duration;
// import java.util.UUID;
// import java.util.stream.Collectors;

// import com.nimbusds.jose.jwk.JWKSet;
// import com.nimbusds.jose.jwk.RSAKey;
// import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
// import com.nimbusds.jose.jwk.source.JWKSource;
// import com.nimbusds.jose.proc.SecurityContext;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.beans.factory.annotation.Value;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.context.annotation.PropertySource;
// import org.springframework.core.annotation.Order;
// import org.springframework.http.MediaType;
// import org.springframework.security.config.Customizer;
// import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.GrantedAuthority;
// // import org.springframework.security.core.userdetails.User;
// // import org.springframework.security.core.userdetails.UserDetails;
// // import org.springframework.security.core.userdetails.UserDetailsService;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.oauth2.core.AuthorizationGrantType;
// import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
// import org.springframework.security.oauth2.core.oidc.OidcScopes;
// import org.springframework.security.oauth2.jwt.JwtDecoder;
// import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
// import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
// import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
// import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
// import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
// import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
// import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
// import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
// import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
// import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
// import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
// // import org.springframework.security.provisioning.InMemoryUserDetailsManager;
// import org.springframework.security.web.SecurityFilterChain;
// import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
// import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

// @Configuration
// @EnableWebSecurity
// // @PropertySource("classpath:env.properties")
// public class SecurityConfig {

//     @Autowired
//     private PasswordEncoder passwordEncoder;

//     // @Value("${CLIENT_ID}")
//     // private String clientId;

//     // @Value("${CLIENT_SECRET}")
//     // private String clientSecret;

//     @Bean 
// 	@Order(1)
// 	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
// 			throws Exception {
// 		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
// 				OAuth2AuthorizationServerConfigurer.authorizationServer();

// 		http
// 			.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
// 			.with(authorizationServerConfigurer, (authorizationServer) ->
// 				authorizationServer
// 					.oidc(Customizer.withDefaults())	// Enable OpenID Connect 1.0
// 			)
// 			// Redirect to the login page when not authenticated from the
// 			// authorization endpoint
// 			.exceptionHandling((exceptions) -> exceptions
// 				.defaultAuthenticationEntryPointFor(
// 					new LoginUrlAuthenticationEntryPoint("/login"),
// 					new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
// 				)
// 			);

// 		return http.build();
// 	}

//     @Bean 
// 	@Order(2)
// 	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
// 			throws Exception {
// 		http
// 			.authorizeHttpRequests((authorize) -> authorize
// 				.anyRequest().authenticated()
// 			)
// 			// Form login handles the redirect to the login page from the
// 			// authorization server filter chain
//             .csrf(csrf -> csrf.disable())
// 			.formLogin(Customizer.withDefaults());

// 		return http.build();
// 	}

//     // este metodo se comento ya que simulaba la obtencion de usuarios
//     // estos eran guardados en memoria, y en la continuaicion del ejemplo, los usuarios son sacados desde
//     // el microservicio 'users' utilizando el metodo 'loadUserByUsername()' de la clase 'UsersService'

//     // @Bean
//     // UserDetailsService userDetailsService() {
//     //         UserDetails userDetails = User.builder()
//     //                         .username("ricardo")
//     //                         .password("{noop}12345")
//     //                         .roles("USER")
//     //                         .build();
//     //         UserDetails admin = User.builder()
//     //                         .username("admin")
//     //                         .password("{noop}12345")
//     //                         .roles("USER", "ADMIN")
//     //                         .build();

//     //         return new InMemoryUserDetailsManager(userDetails, admin);
//     // }

//     @Bean 
// 	public RegisteredClientRepository registeredClientRepository() {
// 		RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
// 				.clientId("gateway-app")
// 				.clientSecret(passwordEncoder.encode("mateo.2501"))
// 				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
// 				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
// 				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
// 				.redirectUri("http://127.0.0.1:8090/login/oauth2/code/client-app")
//                 .redirectUri("http://127.0.0.1:8090/authorized")
// 				.postLogoutRedirectUri("http://127.0.0.1:8090/logout")
// 				.scope(OidcScopes.OPENID)
// 				.scope(OidcScopes.PROFILE)
// 				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
// 				.build();

// 		return new InMemoryRegisteredClientRepository(oidcClient);
// 	}

//     @Bean 
// 	public JWKSource<SecurityContext> jwkSource() {
// 		KeyPair keyPair = generateRsaKey();
// 		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
// 		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
// 		RSAKey rsaKey = new RSAKey.Builder(publicKey)
// 				.privateKey(privateKey)
// 				.keyID(UUID.randomUUID().toString())
// 				.build();
// 		JWKSet jwkSet = new JWKSet(rsaKey);
// 		return new ImmutableJWKSet<>(jwkSet);
// 	}

//     private static KeyPair generateRsaKey() { 
// 		KeyPair keyPair;
// 		try {
// 			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
// 			keyPairGenerator.initialize(2048);
// 			keyPair = keyPairGenerator.generateKeyPair();
// 		}
// 		catch (Exception ex) {
// 			throw new IllegalStateException(ex);
// 		}
// 		return keyPair;
// 	}

//     @Bean 
// 	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
// 		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
// 	}

//     @Bean 
// 	public AuthorizationServerSettings authorizationServerSettings() {
// 		return AuthorizationServerSettings.builder().build();
// 	}

//     // añade los roles del usuario al token, los roles propios de la aplicacion
//     // este metodo permite añadir informacion adicional al token
//     @Bean
//     OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
//         return context -> {
//             if (context.getTokenType().getValue() == OAuth2TokenType.ACCESS_TOKEN.getValue()) {
//                 Authentication principal = context.getPrincipal();
//                 context.getClaims()
//                         .claim("data", "data adicional en el token")
//                         .claim("roles", principal.getAuthorities()
//                                 .stream()
//                                 .map(GrantedAuthority::getAuthority)
//                                 .collect(Collectors.toList()));
//             }
//         };
//     }

// }