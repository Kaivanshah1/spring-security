package app.springsecurity.controller

import app.springsecurity.model.LoginRequest
import app.springsecurity.model.UserRegistrationDto
import app.springsecurity.service.AuthService
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/auth")
class AuthController(val authService: AuthService) {
    @PostMapping("/register")
    fun register(@RequestBody user: UserRegistrationDto): ResponseEntity<Any>{
        return ResponseEntity.ok(authService.registerUser(user))
    }

    @PostMapping("/login")
    fun login(@RequestBody loginRequest: LoginRequest): ResponseEntity<Any>{
        return ResponseEntity.ok(authService.loginUser(loginRequest.username, loginRequest.password))
    }

    @PostMapping("/refresh")
    fun refreshToken( @RequestParam token: String): ResponseEntity<Any?>{
        return ResponseEntity.ok(authService.refreshToken(token))
    }
}

@RestController
@RequestMapping("/public")
class PublicController {
    @GetMapping("/")
    fun getPublic(): ResponseEntity<Any> {
        return ResponseEntity.ok("Public API")
    }
}


@RestController
@RequestMapping("/admin")
class AdminController {
    @GetMapping("/")
    fun getAdmin(): ResponseEntity<Any> {
        return ResponseEntity.ok("Admin API")
    }
}

@RestController
@RequestMapping("/user")
class UserController {
    @GetMapping("/")
    fun getUser(): ResponseEntity<Any> {
        return ResponseEntity.ok("User API")
    }
}

