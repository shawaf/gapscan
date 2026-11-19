import { Request, Response } from "express";

// ruleid: gapscan.javascript.hardcoded-secret
const clientSecret: string = "correct-horse-battery";

export function find(db: any, name: string): void {
  // ruleid: gapscan.javascript.sqli-string-built
  db.query(`SELECT * FROM users WHERE name = '${name}'`);
  // ok: gapscan.javascript.sqli-string-built
  db.query("SELECT * FROM users WHERE name = $1", [name]);
}

export function handler(req: Request, res: Response): void {
  const q: string = "SELECT * FROM users WHERE id = " + req.query.id;
  // ruleid: gapscan.javascript.taint-sqli
  db.query(q);
  // ok: gapscan.javascript.taint-sqli
  db.query("SELECT 1");
}
