const AUTH_FIELDS = [
  "target",
  "username",
  "password",
  "cookie",
  "authorization",
  "login_url",
  "note",
  "raw",
];

export function emptyAuthBinding() {
  return {
    target: "*",
    username: "",
    password: "",
    cookie: "",
    authorization: "",
    login_url: "",
    note: "",
    raw: "",
  };
}

export function showAuthBindingsForSource(source) {
  return ["manual", "both", "site"].includes(String(source || ""));
}

export function parseAuthPaste(value) {
  const text = String(value || "").trim();
  const binding = emptyAuthBinding();
  const target = text.match(/https?:\/\/[^\s]+/i);
  const cookie = text.match(/^\s*Cookie\s*:\s*(.+)$/im);
  const authorization = text.match(/^\s*Authorization\s*:\s*(.+)$/im);
  const credentials = text.match(
    /(?:用户名|账号|帐号|账户|username|user)\s*[:=：]\s*(\S+)[\s\S]{0,40}?(?:密码|password|passwd|pwd)\s*[:=：]\s*(\S+)/i,
  );
  const firstLine = text.split(/\r?\n/).map((line) => line.trim()).find(Boolean) || "";
  const slashPair = firstLine.match(/^([^\s/]{1,64})\s*\/\s*([^\s]{1,128})$/);

  if (target) binding.target = target[0];
  if (cookie) binding.cookie = cookie[1].trim();
  if (authorization) binding.authorization = authorization[1].trim();
  if (credentials) {
    binding.username = credentials[1];
    binding.password = credentials[2];
  } else if (slashPair && !firstLine.includes("=")) {
    binding.username = slashPair[1];
    binding.password = slashPair[2];
  }
  if (!cookie && !authorization && !credentials && !slashPair) {
    binding.raw = text;
  }
  return binding;
}

export function serializeAuthBindings(bindings) {
  return (Array.isArray(bindings) ? bindings : []).flatMap((item) => {
    const normalized = Object.fromEntries(
      AUTH_FIELDS.map((field) => [field, String(item?.[field] || "").trim()]),
    );
    const hasCredential = [
      "username", "password", "cookie", "authorization", "raw",
    ].some((field) => normalized[field]);
    if (!hasCredential) return [];
    if (!normalized.target) normalized.target = "*";
    return [Object.fromEntries(
      Object.entries(normalized).filter(([_field, fieldValue]) => fieldValue),
    )];
  });
}

export function hydrateAuthBindings(bindings) {
  const rows = (Array.isArray(bindings) ? bindings : []).map((item) => ({
    ...emptyAuthBinding(),
    ...Object.fromEntries(
      AUTH_FIELDS.map((field) => [field, String(item?.[field] || "")]),
    ),
  }));
  return rows.length ? rows : [];
}
