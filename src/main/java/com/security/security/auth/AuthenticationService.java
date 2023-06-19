package com.security.security.auth;


import com.security.security.entity.Role;
import com.security.security.entity.User;
import com.security.security.repository.UserRepository;
import com.security.security.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {


    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;


    public AuthenticationResponse register(RegisterRequest registerRequest) {
    var user = User.builder()
            .email(registerRequest.getEmail())
            .password(passwordEncoder.encode(registerRequest.getPassword()))
            .role(Role.USER)
            .build();
    userRepository.save(user);
    var jwtToken = jwtService.generateToken(user);
    return AuthenticationResponse.builder()
            .token(jwtToken)
            .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationRequest.getEmail(),
                        authenticationRequest.getPassword()
                )

        );
        var user = userRepository.findByEmail(authenticationRequest.getEmail()).orElseThrow();
        return AuthenticationResponse.builder()
                .token(jwtService.generateToken(user))
                .build();

    }
}
