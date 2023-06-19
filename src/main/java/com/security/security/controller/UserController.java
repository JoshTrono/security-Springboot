package com.security.security.controller;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    @GetMapping("/testing")
    public ResponseEntity<String> test() {
        return ResponseEntity.ok("Hello World");

    }
    @GetMapping("/admin")
    public ResponseEntity<String> admin() {
        return ResponseEntity.ok("Hello Admin");

    }

}
