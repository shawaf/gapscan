<?php
// Cases for packages/gapscan-security/src/gapscan/rules/semgrep/php: each rule has a vulnerable (ruleid) and a safe (ok) case.

function plain_sql($conn) {
    $id = $_GET['id'];
    // ruleid: gapscan.php.taint-sqli
    $res = mysqli_query($conn, "SELECT * FROM users WHERE id = '" . $id . "'");
    $safe = mysqli_real_escape_string($conn, $_GET['name']);
    // ok: gapscan.php.taint-sqli
    $res = mysqli_query($conn, "SELECT * FROM users WHERE name = '" . $safe . "'");
    $n = (int) $_GET['n'];
    // ok: gapscan.php.taint-sqli
    $res = mysqli_query($conn, "SELECT * FROM t WHERE n = $n");
    // ok: gapscan.php.taint-sqli
    $res = mysqli_query($conn, "SELECT * FROM users");
}

function pdo_sql($pdo) {
    $name = $_POST['name'];
    // ruleid: gapscan.php.taint-sqli
    $rows = $pdo->query("SELECT * FROM users WHERE name = '$name'");
    // ok: gapscan.php.taint-sqli
    $stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?");
    $stmt->execute([$name]);
}

function numeric_guard($conn) {
    $id = $_GET['id'];
    if (is_numeric($id)) {
        // ok: gapscan.php.taint-sqli
        mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
    }
}

function filtered($conn) {
    $id = filter_var($_GET['id'], FILTER_VALIDATE_INT);
    // ok: gapscan.php.taint-sqli
    mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
    // ok: gapscan.php.taint-sqli
    mysqli_query($conn, sprintf("SELECT * FROM users WHERE id = %d", $_GET['id']));
    // ruleid: gapscan.php.taint-sqli
    mysqli_query($conn, sprintf("SELECT * FROM users WHERE name = '%s'", $_GET['name']));
}

function ping() {
    $host = $_REQUEST['host'];
    // ruleid: gapscan.php.taint-command-injection
    $out = shell_exec("ping -c 1 " . $host);
    // ok: gapscan.php.taint-command-injection
    $out = shell_exec("ping -c 1 " . escapeshellarg($host));
}

function page() {
    $p = $_GET['page'];
    // ruleid: gapscan.php.taint-file-inclusion
    include $p . ".php";
    // ok: gapscan.php.taint-file-inclusion
    include "header.php";
    if (in_array($p, ['home', 'about'], true)) {
        // ok: gapscan.php.taint-file-inclusion
        include $p . ".php";
    }
}

function download() {
    $f = $_GET['file'];
    // ruleid: gapscan.php.taint-path-traversal
    readfile("/srv/files/" . $f);
    // ok: gapscan.php.taint-path-traversal
    readfile("/srv/files/" . basename($f));
    // ok: gapscan.php.taint-path-traversal
    $body = file_get_contents('php://input');
}

function fetch() {
    $url = $_GET['url'];
    // ruleid: gapscan.php.taint-ssrf
    $ch = curl_init($url);
    // ok: gapscan.php.taint-ssrf
    $ch = curl_init("https://api.example.com/status");
}

function hello() {
    $name = $_GET['name'];
    // ruleid: gapscan.php.taint-xss
    echo "<p>Hello " . $name . "</p>";
    // ok: gapscan.php.taint-xss
    echo "<p>Hello " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "</p>";
    // ok: gapscan.php.taint-xss
    echo "<p>Hello world</p>";
}

function go() {
    // ruleid: gapscan.php.taint-open-redirect
    header("Location: " . $_GET['next']);
    // ok: gapscan.php.taint-open-redirect
    header("Location: /home");
    // ok: gapscan.php.taint-open-redirect
    header("X-Request: " . urlencode($_GET['next']));
}

function directory($ds) {
    $user = $_GET['user'];
    // ruleid: gapscan.php.taint-ldap-injection
    $r = ldap_search($ds, "dc=example,dc=com", "(uid=" . $user . ")");
    // ok: gapscan.php.taint-ldap-injection
    $r = ldap_search($ds, "dc=example,dc=com", "(uid=" . ldap_escape($user, "", LDAP_ESCAPE_FILTER) . ")");
}

function lookup() {
    $doc = new DOMDocument();
    $xpath = new DOMXPath($doc);
    $name = $_POST['name'];
    // ruleid: gapscan.php.taint-xpath-injection
    $nodes = $xpath->query("//user[name='" . $name . "']");
    // ok: gapscan.php.taint-xpath-injection
    $nodes = $xpath->query("//user");
}

function calc() {
    $expr = $_GET['expr'];
    // ruleid: gapscan.php.taint-code-injection
    eval('$r = ' . $expr . ';');
    // ok: gapscan.php.taint-code-injection
    eval('$r = 1 + 1;');
    // ruleid: gapscan.php.taint-code-injection
    call_user_func($_GET['fn']);
}

function restore() {
    // ruleid: gapscan.php.taint-deserialization, gapscan.php.unserialize-without-allowed-classes
    $obj = unserialize($_COOKIE['state']);
    // ok: gapscan.php.taint-deserialization, gapscan.php.unserialize-without-allowed-classes
    $obj = unserialize($_COOKIE['state'], ['allowed_classes' => false]);
}

function upload() {
    $name = $_FILES['doc']['name'];
    // ruleid: gapscan.php.taint-upload-name, gapscan.php.taint-path-traversal
    move_uploaded_file($_FILES['doc']['tmp_name'], "/var/www/uploads/" . $name);
    // ok: gapscan.php.taint-upload-name
    move_uploaded_file($_FILES['doc']['tmp_name'], "/var/uploads/" . bin2hex(random_bytes(16)) . ".pdf");
}

// ruleid: gapscan.php.extract-request
extract($_POST);
// ok: gapscan.php.extract-request
extract(['a' => 1]);

function passwords($password, $cacheKey) {
    // ruleid: gapscan.php.weak-hash-for-password
    $h = md5($password);
    // ok: gapscan.php.weak-hash-for-password
    $h = password_hash($password, PASSWORD_DEFAULT);
    // ruleid: gapscan.php.weak-hash
    $k = md5($cacheKey);
    // ok: gapscan.php.weak-hash
    $k = hash('sha256', $cacheKey);
}

function tokens() {
    // ruleid: gapscan.php.weak-random-for-secret, gapscan.php.weak-hash
    $resetToken = md5(uniqid());
    // ok: gapscan.php.weak-random-for-secret
    $resetToken = bin2hex(random_bytes(32));
    // ok: gapscan.php.weak-random-for-secret
    $jitter = mt_rand(0, 100);
}

// ruleid: gapscan.php.hardcoded-secret
$apiKey = "sk_live_9f8e7d6c5b4a3210";
// ok: gapscan.php.hardcoded-secret
$apiKey = getenv('API_KEY');
$config = [
    // ruleid: gapscan.php.hardcoded-secret
    'password' => 'Pr0dDbPassw0rd!',
    // ok: gapscan.php.hardcoded-secret
    'host' => 'db.internal',
];

function tls($ch) {
    // ruleid: gapscan.php.tls-verification-disabled
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    // ok: gapscan.php.tls-verification-disabled
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
}

function cookies($sid) {
    // ruleid: gapscan.php.cookie-without-flags
    setcookie("sid", $sid);
    // ok: gapscan.php.cookie-without-flags
    setcookie("sid", $sid, ['expires' => 0, 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
}

// ruleid: gapscan.php.debug-mode-on
ini_set('display_errors', 1);
// ok: gapscan.php.debug-mode-on
ini_set('display_errors', 0);

function crypto($data, $key) {
    // ruleid: gapscan.php.weak-cipher
    $c = openssl_encrypt($data, "des-ede3-cbc", $key);
    // ruleid: gapscan.php.weak-cipher
    $c = openssl_encrypt($data, "aes-128-ecb", $key);
    // ok: gapscan.php.weak-cipher
    $c = openssl_encrypt($data, "aes-256-gcm", $key, 0, $iv, $tag);
}

// ruleid: gapscan.php.mass-assignment-unguarded
class User extends Model {
    protected $guarded = [];
}

// ok: gapscan.php.mass-assignment-unguarded
class Post extends Model {
    protected $fillable = ['title', 'body'];
}

class ReportController extends Controller {
    public function show(Request $request, string $sort, int $page) {
        $q = $request->input('q');
        // ruleid: gapscan.php.taint-sqli, gapscan.php.sqli-string-built
        $rows = DB::select("SELECT * FROM reports WHERE title LIKE '%" . $q . "%'");
        // ok: gapscan.php.sqli-string-built
        $rows = DB::table('items')->whereRaw('price > ?', [$q])->get();
        // ok: gapscan.php.taint-sqli
        $rows = DB::select("SELECT * FROM reports WHERE title LIKE ?", ['%' . $q . '%']);
        // ruleid: gapscan.php.taint-sqli
        $rows = DB::table('reports')->orderByRaw($sort)->get();
        // The pattern rule cannot see the `int` type; the taint rule knows $page is a number.
        // ok: gapscan.php.taint-sqli
        // ruleid: gapscan.php.sqli-string-built
        $rows = DB::select("SELECT * FROM reports LIMIT 10 OFFSET " . $page);
        // ruleid: gapscan.php.taint-open-redirect
        return redirect()->away($request->query('next'));
    }

    public function file($name) {
        // ruleid: gapscan.php.taint-path-traversal
        return response()->download(storage_path('exports/' . $name));
    }
}
