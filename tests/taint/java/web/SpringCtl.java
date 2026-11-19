package web;

import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import java.io.*;

@RestController
public class SpringCtl {
    private JdbcTemplate jdbc;

    @GetMapping("/u")
    public Object user(@RequestParam String name, @RequestParam int age) {
        jdbc.queryForList("SELECT * FROM u WHERE name='" + name + "'"); // VULN:sql
        jdbc.queryForList("SELECT * FROM u WHERE age=" + age); // SAFE
        jdbc.queryForList("SELECT * FROM u WHERE name=?", name); // SAFE
        return null;
    }

    @PostMapping("/p")
    public String path(@PathVariable String id, @RequestBody String body) throws Exception {
        new FileReader("/data/" + id); // VULN:path
        Runtime.getRuntime().exec(body); // VULN:cmd
        return "ok";
    }

    private int helper(int x) { return x + 1; }

    @GetMapping("/n")
    public int numeric(@RequestParam String s) {
        return helper(s.length()); // SAFE
    }
}
