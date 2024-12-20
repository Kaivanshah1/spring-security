package app.springsecurity.service

import app.springsecurity.config.JwtUtil
import app.springsecurity.model.AuthResponse
import app.springsecurity.model.User
import app.springsecurity.model.UserRegistrationDto
import app.springsecurity.repository.UserRepository
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
class AuthService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val jwtUtil: JwtUtil,
    private val userDetailsService: UserDetailsServiceImpl,
    private val authenticationManager: AuthenticationManager

) {
    fun registerUser(userDto: UserRegistrationDto): User {       
        val passwordHash = passwordEncoder.encode(userDto.password) //when registering the hash password is stored, not the plain text password 
        val user = User(username = userDto.username, passwordHash = passwordHash)
        return userRepository.save(user)
    }

    fun loginUser(username: String, password: String): AuthResponse {    // Handles user login and JWT generation.
        // does verification of username and password
        val authToken = UsernamePasswordAuthenticationToken(username, password)
        authenticationManager.authenticate(authToken)

        val userDetails = userDetailsService.loadUserByUsername(username)
        val accessToken = jwtUtil.generateAccessToken(userDetails)
        val refreshToken = jwtUtil.generateRefreshToken(userDetails)
        val user = userRepository.findByUsername(username).get()
        user.refreshToken = refreshToken
        userRepository.save(user)
        return AuthResponse(accessToken = accessToken, refreshToken = refreshToken)
    }

    fun refreshToken(refreshToken: String): AuthResponse? {            
        val username = jwtUtil.extractUsername(refreshToken)     //the jwt refresh token in Header.Payload.Signature format so from the payload the username is extracted 
        val userDetails = userDetailsService.loadUserByUsername(username)  
        val user = userRepository.findByUsername(username).get()  //user is fetch from db
        if (user.refreshToken == refreshToken ) { //matches the refresher token and assignes new tokens  
            val newAccessToken = jwtUtil.generateAccessToken(userDetails) 
            val newRefreshToken = jwtUtil.generateRefreshToken(userDetails)
            user.refreshToken = newRefreshToken
            userRepository.save(user)
            return AuthResponse(accessToken = newAccessToken, refreshToken = newRefreshToken)
        }
        return null
    }
}
