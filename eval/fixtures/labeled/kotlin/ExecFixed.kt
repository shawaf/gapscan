package app.tools

object Diagnostics {
    fun kernel(): String {
        val p = Runtime.getRuntime().exec(arrayOf("uname", "-r"))
        return p.inputStream.bufferedReader().readText().trim()
    }
}
