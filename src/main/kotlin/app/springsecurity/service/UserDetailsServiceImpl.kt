package app.springsecurity.service

import app.springsecurity.repository.UserRepository
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

@Service
class UserDetailsServiceImpl(private val userRepository: UserRepository) : UserDetailsService {

    override fun loadUserByUsername(username: String): UserDetails {
        val user = userRepository.findByUsername(username).orElseThrow { UsernameNotFoundException("User not found with username $username") }

        return User(
            user.username,
            user.passwordHash,
            user.roles.map { it -> org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_$it")}
        )
    }
}