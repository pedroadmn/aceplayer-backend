package com.pedroadmn.aceplayerbackend;

import com.pedroadmn.aceplayerbackend.auth.AuthenticationService;
import com.pedroadmn.aceplayerbackend.auth.RegisterRequest;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import static com.pedroadmn.aceplayerbackend.domain.user.UserRole.ADMIN;
import static com.pedroadmn.aceplayerbackend.domain.user.UserRole.MANAGER;

@SpringBootApplication
public class AceplayerBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(AceplayerBackendApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(
		AuthenticationService authenticationService
	) {
		return args -> {
			var admin = RegisterRequest.builder()
					.firstName("Admin")
					.lastName("Admin")
					.email("admin@mail.com")
					.password("password")
					.role(ADMIN)
					.build();

			System.out.println("Admin token: " + authenticationService.register(admin).getAccessToken());

			var manager = RegisterRequest.builder()
					.firstName("Manger")
					.lastName("Manager")
					.email("manager@mail.com")
					.password("password")
					.role(MANAGER)
					.build();

			System.out.println("Manager token: " + authenticationService.register(manager).getAccessToken());
		};
	}
}
