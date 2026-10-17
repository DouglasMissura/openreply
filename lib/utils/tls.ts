import { checkServerIdentity, type ConnectionOptions } from "node:tls";
import { isIP } from "node:net";
import type { RedisOptions } from "ioredis";

function tlsOptions(ca: string | undefined, hostname: string): ConnectionOptions {
  return {
    minVersion: "TLSv1.2",
    rejectUnauthorized: true,
    ...(ca ? { ca: ca.replace(/\\n/g, "\n") } : {}),
    ...(isIP(hostname) ? {} : { servername: hostname }),
    // pg substitui servername pelo host do proxy. A identidade continua sendo
    // conferida contra o nome do servico cujo certificado a CA autentica.
    checkServerIdentity: (_hostname, cert) => checkServerIdentity(hostname, cert),
  };
}

function parseConnectionUrl(value: string): URL {
  try {
    return new URL(value);
  } catch {
    throw new Error("URL de conexao invalida");
  }
}

export function redisConnectionOptions(url: string): RedisOptions {
  const parsed = parseConnectionUrl(url);
  if (parsed.protocol !== "redis:" && parsed.protocol !== "rediss:") {
    throw new Error("Protocolo Redis invalido");
  }
  // A troca para rediss ocorre apenas depois da implantacao deste cliente.
  if (parsed.protocol === "redis:") {
    if (process.env.REDIS_TLS_CA) throw new Error("CA Redis exige rediss");
    return {};
  }
  if (parsed.search) throw new Error("Parametros Redis TLS nao sao permitidos");
  return { tls: tlsOptions(process.env.REDIS_TLS_CA, parsed.hostname) };
}

export function databaseConnectionOptions(databaseUrl: string) {
  const parsed = parseConnectionUrl(databaseUrl);
  const ca = process.env.DATABASE_TLS_CA;
  const mode = parsed.searchParams.get("sslmode");
  if (!ca && !mode && !parsed.searchParams.has("ssl")) {
    // Preserva a rede interna e permite implantar antes de trocar a URL externa.
    return { connectionString: databaseUrl };
  }
  if (mode && mode !== "verify-full") {
    throw new Error("Postgres TLS exige sslmode=verify-full");
  }
  for (const key of parsed.searchParams.keys()) {
    if ((key.startsWith("ssl") && key !== "sslmode") || key === "uselibpqcompat") {
      throw new Error("Parametros Postgres TLS conflitantes");
    }
  }
  const hostname = process.env.DATABASE_TLS_SERVERNAME || parsed.hostname;
  if (hostname !== parsed.hostname && !ca) {
    throw new Error("Nome Postgres alternativo exige CA fixada");
  }
  parsed.searchParams.delete("sslmode");
  return {
    connectionString: parsed.toString(),
    ssl: tlsOptions(ca, hostname),
  };
}
