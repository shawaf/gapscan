// Cases for packages/gapscan-security/src/gapscan/rules/semgrep/csharp: each rule has a vulnerable (ruleid) and a safe (ok) case.
using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using System.Xml;
using Microsoft.AspNetCore.Mvc;

public class UsersController : Controller
{
    private readonly HttpClient http = new HttpClient();

    public IActionResult Sql()
    {
        var id = Request.Query["id"];
        // ruleid: gapscan.csharp.taint-sqli, gapscan.csharp.sqli-string-built
        var cmd = new SqlCommand("SELECT * FROM users WHERE id = " + id, conn);
        // ok: gapscan.csharp.taint-sqli, gapscan.csharp.sqli-string-built
        var safe = new SqlCommand("SELECT * FROM users WHERE id = @id", conn);
        safe.Parameters.AddWithValue("@id", id);
        var n = int.Parse(Request.Query["n"]);
        // The pattern rule cannot see through `var`; the taint rule knows int.Parse made it a number.
        // ok: gapscan.csharp.taint-sqli
        // ruleid: gapscan.csharp.sqli-string-built
        var numeric = new SqlCommand("SELECT * FROM t WHERE n = " + n, conn);
        int m = int.Parse(Request.Query["m"]);
        // ok: gapscan.csharp.taint-sqli, gapscan.csharp.sqli-string-built
        var typed = new SqlCommand("SELECT * FROM t WHERE m = " + m, conn);
        return Ok();
    }

    public IActionResult Interpolated()
    {
        string name = Request.Form["name"];
        var c = conn.CreateCommand();
        // ruleid: gapscan.csharp.taint-sqli, gapscan.csharp.sqli-string-built
        c.CommandText = $"SELECT * FROM users WHERE name = '{name}'";
        // ok: gapscan.csharp.taint-sqli, gapscan.csharp.sqli-string-built
        c.CommandText = "SELECT * FROM users";
        return Ok();
    }

    public IActionResult Ef(string sort)
    {
        // ruleid: gapscan.csharp.taint-sqli, gapscan.csharp.sqli-string-built
        var rows = db.Users.FromSqlRaw("SELECT * FROM Users ORDER BY " + sort).ToList();
        // ok: gapscan.csharp.taint-sqli, gapscan.csharp.sqli-string-built
        var ok = db.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {sort}").ToList();
        return Ok(rows);
    }

    public IActionResult Dapper(string name)
    {
        // ruleid: gapscan.csharp.taint-dapper-sqli
        var users = connection.Query<User>("SELECT * FROM Users WHERE Name = '" + name + "'");
        // ok: gapscan.csharp.taint-dapper-sqli
        var safe = connection.Query<User>("SELECT * FROM Users WHERE Name = @name", new { name });
        return Ok(users);
    }

    public IActionResult Format(int id)
    {
        // ruleid: gapscan.csharp.sqli-format-string
        var q = string.Format("SELECT * FROM t WHERE id = {0}", id);
        // ok: gapscan.csharp.sqli-format-string
        var msg = string.Format("Hello {0}", id);
        return Ok();
    }

    public IActionResult Ping(string host)
    {
        // ruleid: gapscan.csharp.taint-command-injection
        Process.Start("cmd.exe", "/c ping " + host);
        var psi = new ProcessStartInfo("ping");
        // ok: gapscan.csharp.taint-command-injection
        psi.ArgumentList.Add(host);
        // ok: gapscan.csharp.taint-command-injection
        Process.Start(psi);
        // ruleid: gapscan.csharp.taint-command-injection
        psi.Arguments = "-n 1 " + host;
        // ok: gapscan.csharp.taint-command-injection
        Process.Start("ping", "-n 1 localhost");
        return Ok();
    }

    public IActionResult Download(string file)
    {
        // ruleid: gapscan.csharp.taint-path-traversal
        var text = System.IO.File.ReadAllText("/srv/files/" + file);
        // ok: gapscan.csharp.taint-path-traversal
        var safe = System.IO.File.ReadAllText(Path.Combine("/srv/files", Path.GetFileName(file)));
        string name = Request.Query["name"];
        // ruleid: gapscan.csharp.taint-path-traversal
        using (var reader = new StreamReader(name)) { }
        // ok: gapscan.csharp.taint-path-traversal
        using (var body = new StreamReader(Request.Body)) { }
        // ruleid: gapscan.csharp.taint-path-traversal
        return PhysicalFile("/srv/files/" + file, "application/octet-stream");
    }

    public async System.Threading.Tasks.Task<IActionResult> Fetch(string url)
    {
        // ruleid: gapscan.csharp.taint-ssrf
        var body = await http.GetStringAsync(url);
        // ok: gapscan.csharp.taint-ssrf
        var fixedBody = await http.GetStringAsync("https://api.example.com/status");
        // ruleid: gapscan.csharp.taint-ssrf
        var req = WebRequest.Create(Request.Query["u"]);
        return Ok(body);
    }

    public async System.Threading.Tasks.Task Render()
    {
        var q = Request.Query["q"];
        // ruleid: gapscan.csharp.taint-xss
        await Response.WriteAsync("<div>" + q + "</div>");
        // ok: gapscan.csharp.taint-xss
        await Response.WriteAsync("<div>" + HtmlEncoder.Default.Encode(q) + "</div>");
    }

    public IActionResult Raw(string bio)
    {
        // ruleid: gapscan.csharp.taint-xss
        return Content("<p>" + bio + "</p>", "text/html");
    }

    public IActionResult Go(string returnUrl)
    {
        if (Url.IsLocalUrl(returnUrl))
        {
            // ok: gapscan.csharp.taint-open-redirect
            return Redirect(returnUrl);
        }
        // ruleid: gapscan.csharp.taint-open-redirect
        return Redirect(returnUrl);
    }

    public IActionResult Ldap(string user)
    {
        // ruleid: gapscan.csharp.taint-ldap-injection
        var s = new DirectorySearcher("(&(objectClass=user)(uid=" + user + "))");
        // ok: gapscan.csharp.taint-ldap-injection
        var fixedSearch = new DirectorySearcher("(objectClass=user)");
        return Ok();
    }

    public IActionResult XPath(string name)
    {
        var doc = new XmlDocument();
        // ruleid: gapscan.csharp.taint-xpath-injection
        var nodes = doc.SelectNodes("//user[name='" + name + "']");
        // ok: gapscan.csharp.taint-xpath-injection
        var all = doc.SelectNodes("//user");
        return Ok();
    }

    public async System.Threading.Tasks.Task<IActionResult> Calc(string expr)
    {
        // ruleid: gapscan.csharp.taint-code-injection
        var r = await CSharpScript.EvaluateAsync(expr);
        // ok: gapscan.csharp.taint-code-injection
        var two = await CSharpScript.EvaluateAsync("1 + 1");
        return Ok(r);
    }

    public IActionResult Load()
    {
        // ruleid: gapscan.csharp.insecure-deserializer
        BinaryFormatter f = new BinaryFormatter();
        // ruleid: gapscan.csharp.taint-deserialization
        var o = f.Deserialize(Request.Body);
        return Ok(o);
    }

    public IActionResult Search(string pattern)
    {
        // ruleid: gapscan.csharp.regex-from-input
        var re = new Regex(pattern);
        // ok: gapscan.csharp.regex-from-input
        var escaped = new Regex(Regex.Escape(pattern));
        return Ok();
    }

    // ruleid: gapscan.csharp.csrf-validation-disabled
    [IgnoreAntiforgeryToken]
    public IActionResult Transfer(int amount) { return Ok(); }

    // ruleid: gapscan.csharp.request-validation-disabled
    [ValidateInput(false)]
    public ActionResult Comment(string text) { return View(); }
}

public class Settings
{
    // ruleid: gapscan.csharp.hardcoded-secret
    private const string ApiKey = "sk_live_9f8e7d6c5b4a3210";
    // ok: gapscan.csharp.hardcoded-secret
    private const string Password = "changeme";
    // ruleid: gapscan.csharp.connection-string-password
    string cs = "Server=db01;Database=app;User Id=app;Password=S3cr3tP4ss;";
    // ok: gapscan.csharp.connection-string-password
    string integrated = "Server=db01;Database=app;Integrated Security=true;";

    void Crypto()
    {
        // ruleid: gapscan.csharp.weak-hash
        var md5 = MD5.Create();
        // ok: gapscan.csharp.weak-hash
        var sha = SHA256.Create();
        // ruleid: gapscan.csharp.weak-cipher
        var des = DES.Create();
        var aes = Aes.Create();
        // ruleid: gapscan.csharp.weak-cipher
        aes.Mode = CipherMode.ECB;
        // ok: gapscan.csharp.weak-cipher
        aes.Mode = CipherMode.CBC;
        // ruleid: gapscan.csharp.weak-random-for-secret
        var resetToken = new Random().Next(100000, 999999);
        // ok: gapscan.csharp.weak-random-for-secret
        var jitter = new Random().Next(0, 100);
    }

    void Tls()
    {
        var handler = new HttpClientHandler();
        // ruleid: gapscan.csharp.tls-validation-disabled
        handler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true;
        // ruleid: gapscan.csharp.tls-validation-disabled
        handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        // ok: gapscan.csharp.tls-validation-disabled
        handler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => errors == System.Net.Security.SslPolicyErrors.None;
    }

    void Serializers(string json)
    {
        // ruleid: gapscan.csharp.insecure-deserializer
        var bf = new BinaryFormatter();
        // ruleid: gapscan.csharp.jsonnet-type-name-handling
        var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
        // ok: gapscan.csharp.jsonnet-type-name-handling
        var t = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };
    }

    void Xml(string xml)
    {
        var settings = new XmlReaderSettings();
        // ruleid: gapscan.csharp.xxe-dtd-processing
        settings.DtdProcessing = DtdProcessing.Parse;
        // ok: gapscan.csharp.xxe-dtd-processing
        settings.DtdProcessing = DtdProcessing.Prohibit;
        // ruleid: gapscan.csharp.xxe-xmldocument-default-resolver
        var doc = new XmlDocument();
        doc.LoadXml(xml);
    }

    void XmlSafe(string xml)
    {
        // ok: gapscan.csharp.xxe-xmldocument-default-resolver
        var doc = new XmlDocument();
        doc.XmlResolver = null;
        doc.LoadXml(xml);
    }

    void Cookies(HttpResponse response)
    {
        // ruleid: gapscan.csharp.cookie-without-flags
        response.Cookies.Append("sid", "x", new CookieOptions { HttpOnly = false, Secure = true });
        // ok: gapscan.csharp.cookie-without-flags
        response.Cookies.Append("sid", "x", new CookieOptions { HttpOnly = true, Secure = true });
    }

    void Configure(IApplicationBuilder app, IWebHostEnvironment env, IServiceCollection services)
    {
        // ruleid: gapscan.csharp.developer-exception-page
        app.UseDeveloperExceptionPage();
        if (env.IsDevelopment())
        {
            // ok: gapscan.csharp.developer-exception-page
            app.UseDeveloperExceptionPage();
        }
        services.AddCors(o => o.AddPolicy("p", b =>
            // ruleid: gapscan.csharp.cors-any-origin-with-credentials
            b.SetIsOriginAllowed(_ => true).AllowCredentials()));
        services.AddCors(o => o.AddPolicy("q", b =>
            // ok: gapscan.csharp.cors-any-origin-with-credentials
            b.WithOrigins("https://app.example.com").AllowCredentials()));
        var p = new TokenValidationParameters
        {
            // ruleid: gapscan.csharp.jwt-validation-disabled
            ValidateLifetime = false,
            // ok: gapscan.csharp.jwt-validation-disabled
            ValidateIssuer = true,
        };
    }
}
