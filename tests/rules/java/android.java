import android.app.PendingIntent;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.net.Uri;
import android.os.Environment;
import android.database.sqlite.SQLiteQueryBuilder;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;
import android.webkit.WebView;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AndroidCases extends android.app.Activity {

    void sql(SQLiteDatabase db, String name) {
        // ruleid: gapscan.java.android-sql-string-built
        db.rawQuery("SELECT * FROM users WHERE user = '" + name + "'", null);
        // ruleid: gapscan.java.android-sql-string-built
        db.execSQL("DELETE FROM t WHERE id = " + name);
        // ok: gapscan.java.android-sql-string-built
        db.rawQuery("SELECT * FROM users WHERE user = ?", new String[] {name});
        // ok: gapscan.java.android-sql-string-built
        db.execSQL("DROP TABLE IF EXISTS users;");
    }

    void logs(android.widget.EditText cc, String password, String message) {
        // ruleid: gapscan.java.android-log-user-input
        Log.e("tag", "Error with card " + cc.getText().toString());
        // ruleid: gapscan.java.android-log-user-input
        Log.d("tag", "login " + password);
        // ok: gapscan.java.android-log-user-input
        Log.d("tag", "login failed");
    }

    void prefs(SharedPreferences.Editor editor, android.widget.EditText user, String value) {
        // ruleid: gapscan.java.android-prefs-sensitive
        editor.putString("password", value);
        // ruleid: gapscan.java.android-prefs-sensitive
        editor.putString("k", user.getText().toString());
        // ok: gapscan.java.android-prefs-sensitive
        editor.putString("theme", "dark");
    }

    void files() throws Exception {
        // ruleid: gapscan.java.android-world-accessible-file
        getSharedPreferences("p", Context.MODE_WORLD_READABLE);
        // ok: gapscan.java.android-world-accessible-file
        getSharedPreferences("p", Context.MODE_PRIVATE);
        // ruleid: gapscan.java.android-external-storage
        java.io.File sd = Environment.getExternalStorageDirectory();
    }

    void webviews(WebView w, android.webkit.WebSettings s) {
        // ruleid: gapscan.java.android-webview-risky-settings
        w.addJavascriptInterface(new Object(), "bridge");
        // ruleid: gapscan.java.android-webview-risky-settings
        s.setAllowFileAccess(true);
        // ok: gapscan.java.android-webview-risky-settings
        s.setAllowFileAccess(false);
    }

    class Client extends android.webkit.WebViewClient {
        public void onReceivedSslError(WebView v, android.webkit.SslErrorHandler h, android.net.http.SslError e) {
            // ruleid: gapscan.java.android-webview-ssl-error-ignored
            h.proceed();
        }
    }

    class SafeClient extends android.webkit.WebViewClient {
        public void onReceivedSslError(WebView v, android.webkit.SslErrorHandler h, android.net.http.SslError e) {
            // ok: gapscan.java.android-webview-ssl-error-ignored
            h.cancel();
        }
    }

    void crypto(byte[] raw) {
        // ruleid: gapscan.java.android-hardcoded-key
        new SecretKeySpec("This is the super secret key 123".getBytes(), "AES");
        // ruleid: gapscan.java.android-hardcoded-key
        new IvParameterSpec(new byte[16]);
        // ok: gapscan.java.android-hardcoded-key
        new SecretKeySpec(raw, "AES");
    }

    void credentials(android.widget.EditText input) {
        // ruleid: gapscan.java.android-hardcoded-credential
        String details = "TVEETER API Key: secrettveeterapikey\nAPI User name: diva2\nAPI Password: p@ssword2";
        // ruleid: gapscan.java.android-hardcoded-credential
        boolean ok = input.getText().toString().equals("vendorsecretkey");
        // ok: gapscan.java.android-hardcoded-credential
        String label = "Enter your password";
    }

    void urls() {
        // ruleid: gapscan.java.android-cleartext-url
        String api = "http://payatu.com/login";
        // ok: gapscan.java.android-cleartext-url
        String safe = "https://payatu.com/login";
        // ok: gapscan.java.android-cleartext-url
        String local = "http://10.0.2.2:8888/login";
    }

    void storage2(SQLiteDatabase db, String usr, String pwd) throws Exception {
        // ruleid: gapscan.java.android-temp-file-credentials
        java.io.File tmp = java.io.File.createTempFile("uinfo", "tmp");
        // ruleid: gapscan.java.android-credentials-in-database, gapscan.java.android-sql-string-built
        db.execSQL("INSERT INTO myuser VALUES ('" + usr + "', '" + pwd + "');");
        // ok: gapscan.java.android-credentials-in-database
        db.execSQL("INSERT INTO settings VALUES ('theme', 'dark');");
    }

    void pending(Context c, android.content.Intent i) {
        // ruleid: gapscan.java.android-pendingintent-mutable
        PendingIntent.getActivity(c, 0, i, PendingIntent.FLAG_UPDATE_CURRENT);
        // ok: gapscan.java.android-pendingintent-mutable
        PendingIntent.getActivity(c, 0, i, PendingIntent.FLAG_IMMUTABLE);
    }
}

class NotesLike extends android.content.ContentProvider {
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        SQLiteQueryBuilder qb = new SQLiteQueryBuilder();
        // ruleid: gapscan.java.android-provider-sql-injection
        return qb.query(mDB, projection, selection, selectionArgs, null, null, sortOrder);
    }
}
