package com.example.server

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.ktor.http.ContentType
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.plugins.cors.routing.CORS
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respondFile
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import org.jetbrains.exposed.sql.transactions.transaction
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.io.File
import java.net.URL
import javax.sql.DataSource

fun Application.routes(client: io.ktor.client.HttpClient) {
    routing {
        get("/notes") {
            val owner = call.request.queryParameters["owner"]
            transaction {
                // ruleid: gapscan.kotlin.taint-sqli
                exec("SELECT * FROM notes WHERE owner = '$owner'")
            }
            val id = call.parameters["id"]!!.toInt()
            // ok: gapscan.kotlin.taint-sqli
            exec("SELECT * FROM notes WHERE id = $id")
        }
        post("/ping") {
            val params = call.receiveParameters()
            val host = params["host"]
            // ruleid: gapscan.kotlin.taint-command-injection
            ProcessBuilder("sh", "-c", "ping -c 1 $host").start()
            // ok: gapscan.kotlin.taint-command-injection
            ProcessBuilder("uptime").start()
            // ruleid: gapscan.kotlin.taint-command-injection
            Runtime.getRuntime().exec("ping -c 1 " + host)
            // ruleid: gapscan.kotlin.taint-sqli
            TransactionManager.current().exec("DELETE FROM hosts WHERE name = '$host'")
        }
        get("/files/{name}") {
            val name = call.parameters["name"]!!
            // ruleid: gapscan.kotlin.taint-path-traversal
            call.respondFile(File("/srv/uploads", name))
            // ok: gapscan.kotlin.taint-path-traversal
            call.respondFile(File("/srv/uploads", File(name).name))
        }
        get("/fetch") {
            val target = call.request.queryParameters["url"]!!
            // ruleid: gapscan.kotlin.taint-ssrf
            val body = URL(target).readText()
            // ruleid: gapscan.kotlin.taint-ssrf
            client.get(target)
            // ok: gapscan.kotlin.taint-ssrf
            client.get("https://api.example.com/status")
        }
        get("/login/done") {
            val next = call.request.queryParameters["next"]!!
            // ruleid: gapscan.kotlin.taint-open-redirect
            call.respondRedirect(next)
            // ok: gapscan.kotlin.taint-open-redirect
            call.respondRedirect("/home")
        }
        get("/hello") {
            val who = call.request.queryParameters["name"]
            // ruleid: gapscan.kotlin.taint-xss
            call.respondText("<h1>Hello $who</h1>", ContentType.Text.Html)
            // ok: gapscan.kotlin.taint-xss
            call.respondText("Hello $who", ContentType.Text.Plain)
        }
        post("/calc") {
            val expr = call.receiveText()
            // ruleid: gapscan.kotlin.taint-code-injection
            val v = SpelExpressionParser().parseExpression(expr).getValue()
            // ok: gapscan.kotlin.taint-code-injection
            val w = SpelExpressionParser().parseExpression("1 + 1").getValue()
        }
    }
}

@RestController
class NotesController(private val jdbc: JdbcTemplate, private val ds: DataSource) {
    @GetMapping("/api/notes")
    fun search(@RequestParam q: String): List<Map<String, Any>> {
        // ruleid: gapscan.kotlin.taint-sqli
        return jdbc.queryForList("SELECT * FROM notes WHERE title LIKE '%$q%'")
    }

    @GetMapping("/api/notes/{id}")
    fun one(@PathVariable("id") id: String): Any? {
        val st = ds.connection.createStatement()
        // ruleid: gapscan.kotlin.taint-sqli
        st.executeQuery("SELECT * FROM notes WHERE id = " + id)
        // ok: gapscan.kotlin.taint-sqli
        return jdbc.queryForObject("SELECT * FROM notes WHERE id = ?", Any::class.java, id)
    }

    fun internal(title: String) {
        // ok: gapscan.kotlin.taint-sqli
        jdbc.queryForList("SELECT * FROM notes WHERE title = '$title'")
    }

    @GetMapping("/go")
    fun go(@RequestParam url: String): String {
        // ruleid: gapscan.kotlin.taint-open-redirect
        return "redirect:" + url
    }
}

class Tokens {
    fun user(token: String): String {
        // ruleid: gapscan.kotlin.jwt-unverified
        return JWT.decode(token).subject
    }

    fun verifiedUser(token: String): String {
        val verifier = JWT.require(Algorithm.HMAC256(System.getenv("JWT_KEY"))).build()
        verifier.verify(token)
        // ok: gapscan.kotlin.jwt-unverified
        return JWT.decode(token).subject
    }

    fun none() {
        // ruleid: gapscan.kotlin.jwt-unverified
        val alg = Algorithm.none()
        // ruleid: gapscan.kotlin.jwt-hardcoded-secret
        val signer = Algorithm.HMAC256("super-secret-signing-key")
        // ok: gapscan.kotlin.jwt-hardcoded-secret
        val good = Algorithm.HMAC256(System.getenv("JWT_KEY"))
    }
}

fun Application.cors() {
    // ruleid: gapscan.kotlin.cors-any-origin-with-credentials
    install(CORS) {
        anyHost()
        allowCredentials = true
    }
}

fun Application.corsOk() {
    // ok: gapscan.kotlin.cors-any-origin-with-credentials
    install(CORS) {
        allowHost("app.example.com", schemes = listOf("https"))
        allowCredentials = true
    }
}

class WebConfig : WebMvcConfigurer {
    override fun addCorsMappings(registry: CorsRegistry) {
        // ruleid: gapscan.kotlin.cors-any-origin-with-credentials
        registry.addMapping("/**").allowedOriginPatterns("*").allowCredentials(true)
        // ok: gapscan.kotlin.cors-any-origin-with-credentials
        registry.addMapping("/public/**").allowedOrigins("https://app.example.com").allowCredentials(true)
    }
}

class SecurityConfig {
    fun chain(http: HttpSecurity) {
        // ruleid: gapscan.kotlin.csrf-protection-disabled
        http.csrf().disable()
        http {
            // ruleid: gapscan.kotlin.csrf-protection-disabled
            csrf { disable() }
        }
        // ok: gapscan.kotlin.csrf-protection-disabled
        http.csrf { it.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) }
    }

    fun cookies(cookie: javax.servlet.http.Cookie) {
        // ruleid: gapscan.kotlin.cookie-insecure-flags
        cookie.secure = false
        // ruleid: gapscan.kotlin.cookie-insecure-flags
        cookie.isHttpOnly = false
        // ok: gapscan.kotlin.cookie-insecure-flags
        cookie.secure = true
    }
}
