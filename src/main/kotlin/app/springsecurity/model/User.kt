package app.springsecurity.model

import org.springframework.data.annotation.Id
import org.springframework.data.mongodb.core.mapping.Document

@Document(collection = "users")
data class User(        //this is used to stored in db 
    @Id
    var id: String? = null,
    var username: String,
    var passwordHash: String,
    var roles: List<String> = listOf("USER"),
    var refreshToken : String? = null
)

data class UserRegistrationDto( //this is used every time the registration request is send 
    val username: String,
    val password: String,
    val roles: List<String> = listOf("USER")
)

data class LoginRequest(  //this is used when login request is send 
    val username: String,
    val password: String
)

data class AuthResponse(val accessToken: String, val refreshToken: String)
