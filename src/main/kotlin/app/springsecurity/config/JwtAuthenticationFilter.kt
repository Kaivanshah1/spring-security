package app.springsecurity.config

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.HttpHeaders
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class JwtAuthenticationFilter(private val jwtUtil: JwtUtil) : OncePerRequestFilter() {
    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
        val authHeader = request.getHeader(HttpHeaders.AUTHORIZATION)

        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response)
            return
        }
        val token = authHeader.substring(7) // remove bearer

        val username = jwtUtil.extractUsername(token)

        if(username != null && SecurityContextHolder.getContext().authentication == null) {
            val roles = jwtUtil.extractRoles(token)

            if(jwtUtil.isTokenExpired(token)) {
                filterChain.doFilter(request, response)
                return
            }
            val authorities = roles.map { role -> SimpleGrantedAuthority("ROLE_$role") }
            val authentication = UsernamePasswordAuthenticationToken(username, null, authorities)

            SecurityContextHolder.getContext().authentication = authentication
        }
        filterChain.doFilter(request, response)
    }
}