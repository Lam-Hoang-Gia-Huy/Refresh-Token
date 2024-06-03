package com.example.JWTImplemenation.Auth;

import com.example.JWTImplemenation.DTO.AuthenticationRequest;
import com.example.JWTImplemenation.DTO.RefreshTokenRequest;
import com.example.JWTImplemenation.DTO.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService service;
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponese> register(
            @RequestBody RegisterRequest request
    ){
        return ResponseEntity.ok(service.register(request));
    }
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponese> authenticate(
            @RequestBody AuthenticationRequest request
    ){
        return ResponseEntity.ok(service.authenticate(request));
    }
    @PostMapping("/refresh-token")
    public ResponseEntity<AuthenticationResponese> refreshToken(
            @RequestBody RefreshTokenRequest refreshTokenRequest
    ){
        return ResponseEntity.ok(service.refreshToken(refreshTokenRequest));
    }
}
