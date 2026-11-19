package svc;

import java.util.*;

public class Util {
    public static String clean(String s) { return s.trim(); }
    public static String sanitize(String s) { return s.replaceAll("[^a-zA-Z0-9]", ""); }
    public static String join(String a, String b) { return a + "/" + b; }
    public static String firstOf(List<String> xs) { return xs.get(0); }
    public static String constant() { return "static-value"; }
    public static String wrap(String s) {
        StringBuilder sb = new StringBuilder();
        sb.append("<b>").append(s).append("</b>");
        return sb.toString();
    }
}
