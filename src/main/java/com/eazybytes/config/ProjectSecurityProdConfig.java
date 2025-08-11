package com.eazybytes.config;

import com.eazybytes.exceptionhandling.CustomAccessDeniedHandler;
import com.eazybytes.exceptionhandling.CustomBasicAuthenticationEntryPoint;
import com.eazybytes.filter.CsrfCookieFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

@Configuration
@Profile("prod")
public class ProjectSecurityProdConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());
        /*http.authorizeHttpRequests((requests) -> requests.anyRequest().permitAll());*/
        /*http.authorizeHttpRequests((requests) -> requests.anyRequest().denyAll());*/
        CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();
        http.securityContext(contextConfig -> contextConfig.requireExplicitSave(false))
                .sessionManagement(sessionConfig -> sessionConfig.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
                .cors(corsConfig -> corsConfig.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration config = new CorsConfiguration();
                        config.setAllowedOrigins(Collections.singletonList("https://localhost:4200"));
                        config.setAllowedMethods(Collections.singletonList("*"));
                        config.setAllowCredentials(true);
                        config.setAllowedHeaders(Collections.singletonList("*"));
                        config.setExposedHeaders(Arrays.asList("Authorization"));
                        config.setMaxAge(3600L);
                        return config;
                    }
                }))
                .csrf(csrfConfig -> csrfConfig.csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
                        .ignoringRequestMatchers( "/contact","/register")
//                        .ignoringRequestMatchers( "/contact","/register", "/apiLogin")
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
                /*.addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(new AuthoritiesLoggingAfterFilter(), BasicAuthenticationFilter.class)
                .addFilterAt(new AuthoritiesLoggingAtFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(new JWTTokenGeneratorFilter(), BasicAuthenticationFilter.class)
                .addFilterBefore(new JWTTokenValidatorFilter(), BasicAuthenticationFilter.class)*/
//                .sessionManagement(smc -> smc.invalidSessionUrl("/invalidSession").maximumSessions(1).maxSessionsPreventsLogin(true))
                .redirectToHttps((https) -> https.requestMatchers(AnyRequestMatcher.INSTANCE))
//                .csrf(csrfConfig -> csrfConfig.disable())
                .authorizeHttpRequests((requests) -> requests
                /*.requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
                .requestMatchers("/myBalance").hasAnyAuthority("VIEWBALANCE", "VIEWACCOUNT")
                .requestMatchers("/myLoans").hasAuthority("VIEWLOANS")
                .requestMatchers("/myCards").hasAuthority("VIEWCARDS")*/
                .requestMatchers("/myAccount").hasRole("USER")
                .requestMatchers("/myBalance").hasAnyRole("USER", "ADMIN")
                .requestMatchers("/myLoans").hasRole("USER")
                .requestMatchers("/myCards").hasRole("USER")
                .requestMatchers("/user").authenticated()
                .requestMatchers("/notices", "/contact", "/error", "/register").permitAll());
//                .requestMatchers("/notices", "/contact", "/error", "/register", "/invalidSession", "/apiLogin").permitAll());
        http.oauth2ResourceServer(rsc -> rsc.jwt(jwtConfigurer ->
                jwtConfigurer.jwtAuthenticationConverter(jwtAuthenticationConverter)));
//        http.formLogin(withDefaults());
//        http.formLogin(flc -> flc.disable());
        http.httpBasic(hbc -> hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
//        http.httpBasic(hbc -> hbc.disable());
        http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));
        return http.build();
    }

   /* @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user").password("{noop}Sangramjit@12345").authorities("read").build();
        UserDetails admin = User.withUsername("admin")
                .password("{bcrypt}$2a$12$BWqflYs3RBGS1ucjFiihO.1xVrDaon2eSpU0w7d1zkJT/ggwFcn9y")
                .authorities("admin").build();
        return new InMemoryUserDetailsManager(user, admin);
    }*/

    /*@Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }*/

    /*@Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    *//**
     * From Spring Security 6.3 version
     * @return
     *//*
    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService,
                                                       PasswordEncoder passwordEncoder) {
        EazyBankProdUsernamePwdAuthenticationProvider authenticationProvider =
                new EazyBankProdUsernamePwdAuthenticationProvider(userDetailsService, passwordEncoder);
        ProviderManager providerManager = new ProviderManager(authenticationProvider);
        providerManager.setEraseCredentialsAfterAuthentication(false);
        return  providerManager;
    }*/
}
