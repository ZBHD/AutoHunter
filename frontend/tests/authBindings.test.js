import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  emptyAuthBinding,
  parseAuthPaste,
  serializeAuthBindings,
  showAuthBindingsForSource,
} from "../src/authBindings.js";


test("auth bindings are shown only for target-bound source modes", () => {
  assert.equal(showAuthBindingsForSource("fofa"), false);
  assert.equal(showAuthBindingsForSource("manual"), true);
  assert.equal(showAuthBindingsForSource("both"), true);
  assert.equal(showAuthBindingsForSource("site"), true);
});


test("quick paste extracts target, cookie, bearer and password credentials", () => {
  const parsed = parseAuthPaste(`
https://portal.example/login
Cookie: sid=abc; theme=dark
Authorization: Bearer token-1
username: alice password: secret
  `);

  assert.deepEqual(parsed, {
    target: "https://portal.example/login",
    username: "alice",
    password: "secret",
    cookie: "sid=abc; theme=dark",
    authorization: "Bearer token-1",
    login_url: "",
    note: "",
    raw: "",
  });
});


test("serialization trims fields and omits empty rows", () => {
  assert.deepEqual(serializeAuthBindings([
    { ...emptyAuthBinding(), target: " portal.example ", cookie: " sid=abc " },
    emptyAuthBinding(),
  ]), [{ target: "portal.example", cookie: "sid=abc" }]);
});


test("task forms wire the shared auth editor and task payload", () => {
  const create = readFileSync(
    new URL("../src/views/CreateView.vue", import.meta.url), "utf8",
  );
  const edit = readFileSync(
    new URL("../src/components/TaskEditModal.vue", import.meta.url), "utf8",
  );
  for (const source of [create, edit]) {
    assert.match(source, /AuthBindingsEditor/);
    assert.match(source, /showAuthBindingsForSource/);
    assert.match(source, /auth_bindings:/);
  }
  assert.match(edit, /hydrateAuthBindings\(task\.auth_bindings/);
});


test("board renders redacted authentication state only", () => {
  const board = readFileSync(
    new URL("../src/views/BoardView.vue", import.meta.url), "utf8",
  );
  assert.match(board, /auth_status/);
  assert.match(board, /authStatusLabel/);
  assert.doesNotMatch(board, /auth_context/);
});
