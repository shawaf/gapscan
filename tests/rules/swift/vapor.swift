import Vapor
import SQLKit
import JWT

func routes(_ app: Application) throws {
    app.get("ping") { req -> String in
        let host = req.query["host"] ?? ""
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        // ruleid: gapscan.swift.vapor-taint-command
        p.arguments = ["-c", "ping -c 1 " + host]
        try p.run()
        return "ok"
    }

    app.get("uptime") { req -> String in
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/uptime")
        // ok: gapscan.swift.vapor-taint-command
        p.arguments = ["-p"]
        try p.run()
        return "ok"
    }

    app.get("files", ":name") { req -> Response in
        let name = req.parameters.get("name") ?? ""
        // ruleid: gapscan.swift.vapor-taint-path-traversal
        let data = FileManager.default.contents(atPath: "/srv/files/" + name)
        return Response(body: .init(data: data ?? Data()))
    }

    app.get("safe-files", ":name") { req -> Response in
        let name = URL(fileURLWithPath: req.parameters.get("name") ?? "").lastPathComponent
        // ok: gapscan.swift.vapor-taint-path-traversal
        let data = FileManager.default.contents(atPath: "/srv/files/" + name)
        return Response(body: .init(data: data ?? Data()))
    }

    app.get("fetch") { req async throws -> String in
        let target = req.query["url"] ?? ""
        // ruleid: gapscan.swift.vapor-taint-ssrf
        let res = try await req.client.get(URI(string: target))
        return "\(res.status)"
    }

    app.get("status") { req async throws -> String in
        // ok: gapscan.swift.vapor-taint-ssrf
        let res = try await req.client.get(URI(string: "https://status.example.com/api"))
        return "\(res.status)"
    }

    app.get("login", "done") { req -> Response in
        let next: String = try req.query.get(String.self, at: "next")
        // ruleid: gapscan.swift.vapor-taint-open-redirect
        return req.redirect(to: next)
    }

    app.get("logout") { req -> Response in
        // ok: gapscan.swift.vapor-taint-open-redirect
        return req.redirect(to: "/")
    }

    app.get("search") { req async throws -> [Row] in
        let term = req.query["q"] ?? ""
        let sql = req.db as! SQLDatabase
        // ruleid: gapscan.swift.vapor-taint-sql
        return try await sql.raw(SQLQueryString("SELECT * FROM items WHERE name = '" + term + "'")).all(decoding: Row.self)
    }

    app.get("pg") { req async throws -> String in
        let term = req.query["q"] ?? ""
        let conn = try await pool.connection()
        // ruleid: gapscan.swift.vapor-taint-sql
        let rows = try await conn.query("SELECT * FROM items WHERE name = '\(term)'", logger: req.logger)
        // ok: gapscan.swift.vapor-taint-sql
        let all = try await conn.query("SELECT * FROM items", logger: req.logger)
        return "\(rows) \(all)"
    }

    app.get("item", ":id") { req async throws -> [Row] in
        let id = Int(req.parameters.get("id") ?? "") ?? 0
        let sql = req.db as! SQLDatabase
        // ok: gapscan.swift.vapor-taint-sql
        return try await sql.raw(SQLQueryString("SELECT * FROM items WHERE id = \(id)")).all(decoding: Row.self)
    }

    app.post("users") { req async throws -> [User] in
        let input = try req.content.decode(Search.self)
        let sql = req.db as! SQLDatabase
        // ruleid: gapscan.swift.sqlkit-raw-interpolation
        let bad = try await sql.raw("SELECT * FROM users WHERE name = '\(raw: input.name)'").all(decoding: User.self)
        // ok: gapscan.swift.sqlkit-raw-interpolation
        let good = try await sql.raw("SELECT * FROM users WHERE name = \(bind: input.name)").all(decoding: User.self)
        return bad + good
    }

    app.get("me") { req async throws -> String in
        let bearer = req.headers.bearerAuthorization?.token ?? ""
        // ruleid: gapscan.swift.jwt-verification-disabled
        let claims = try req.application.jwt.signers.unverified(bearer, as: UserClaims.self)
        // ok: gapscan.swift.jwt-verification-disabled
        let verified = try req.jwt.verify(as: UserClaims.self)
        return claims.sub.value + verified.sub.value
    }
}

func configure(_ app: Application) throws {
    // ruleid: gapscan.swift.jwt-hardcoded-key
    app.jwt.signers.use(.hs256(key: "change-me-please-0123456789"))
    // ok: gapscan.swift.jwt-hardcoded-key
    app.jwt.signers.use(.hs256(key: Environment.get("JWT_SECRET")!))
    // ruleid: gapscan.swift.vapor-plaintext-passwords
    app.passwords.use(.plaintext)
    // ok: gapscan.swift.vapor-plaintext-passwords
    app.passwords.use(.bcrypt)
}
