package app.lumbral.backend.auth.config;

import app.lumbral.backend.auth.filter.JwtAuthenticationEntryPoint;
import app.lumbral.backend.auth.filter.JwtAuthenticationFilter;
import app.lumbral.backend.auth.repository.TenantMembershipRepository;
import app.lumbral.backend.auth.service.JwtService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Value("${app.cors.allowed-origins:}")
	private String allowedOriginsConfig;

	@Bean
	public JwtAuthenticationFilter jwtAuthenticationFilter(JwtService jwtService,
														   TenantMembershipRepository membershipRepository,
														   ObjectMapper objectMapper) {
		return new JwtAuthenticationFilter(jwtService, membershipRepository, objectMapper);
	}

	@Bean
	public JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint(ObjectMapper objectMapper) {
		return new JwtAuthenticationEntryPoint(objectMapper);
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http,
												   JwtAuthenticationFilter jwtFilter,
												   JwtAuthenticationEntryPoint entryPoint) throws Exception {
		return http
				.csrf(AbstractHttpConfigurer::disable)
				.logout(AbstractHttpConfigurer::disable)
				.cors(cors -> cors.configurationSource(corsConfigurationSource()))
				.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.exceptionHandling(ex -> ex.authenticationEntryPoint(entryPoint))
				.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
				.authorizeHttpRequests(auth -> auth
						.requestMatchers("/actuator/health/**").permitAll()
						.requestMatchers("/api/public/**").permitAll()
						.requestMatchers("/api/v1/auth/**").permitAll()
						.anyRequest().authenticated())
				.build();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		List<String> origins = allowedOriginsConfig == null || allowedOriginsConfig.isBlank()
				? List.of()
				: Arrays.stream(allowedOriginsConfig.split(",")).map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toList());
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowedOrigins(origins);
		config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
		config.setAllowedHeaders(List.of("*"));
		config.setAllowCredentials(true);
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", config);
		return source;
	}
}
