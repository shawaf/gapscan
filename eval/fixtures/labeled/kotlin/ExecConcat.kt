package app.tools

import io.ktor.server.application.call
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get

fun Route.ping() {
    get("/ping") {
        val host = call.request.queryParameters["host"] ?: ""
        val p = Runtime.getRuntime().exec("ping -c 1 " + host)
        call.respondText(p.inputStream.bufferedReader().readText())
    }
}
