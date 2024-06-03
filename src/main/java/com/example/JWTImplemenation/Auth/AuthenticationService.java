package com.example.JWTImplemenation.Auth;

import com.example.JWTImplemenation.DTO.AuthenticationRequest;
import com.example.JWTImplemenation.DTO.RefreshTokenRequest;
import com.example.JWTImplemenation.DTO.RegisterRequest;
import com.example.JWTImplemenation.Repository.UserRepository;
import com.example.JWTImplemenation.Service.JwtService;
import com.example.JWTImplemenation.User.Role;
import com.example.JWTImplemenation.User.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder PasswordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponese register(RegisterRequest request) {
        var user = User.builder()
                .firstName(request.getFirstname())
                .lastName(request.getLastname())
                .email(request.getEmail())
                .password(PasswordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);
        var jwtToken=jwtService.generateToken(user);
        return AuthenticationResponese.builder().token(jwtToken).build();
    }

    public AuthenticationResponese authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
                );
        var user=userRepository.findByEmail(request.getEmail()).orElseThrow();
        var token=jwtService.generateToken(user);
        var refreshToken=jwtService.generateRefreshToken(user);
        return AuthenticationResponese.builder().token(token).refreshToken(refreshToken).build();
    }

    public AuthenticationResponese refreshToken(RefreshTokenRequest refreshTokenRequest) {
        String userEmail = jwtService.extractUsername(refreshTokenRequest.getToken());
        User user = userRepository.findByEmail(userEmail).orElseThrow();
        if (jwtService.isTokenValid(refreshTokenRequest.getToken(), user)) {
            var jwt = jwtService.generateToken(user);

            AuthenticationResponese authenticationResponse = new AuthenticationResponese();
            authenticationResponse.setToken(jwt);
            authenticationResponse.setRefreshToken(refreshTokenRequest.getToken());
            return authenticationResponse;
        }
        return null;
    }
}
