export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "");

    const corsHeaders = {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,PUT,OPTIONS",
      "access-control-allow-headers": "content-type",
      "access-control-max-age": "86400",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const match = path.match(/^\/v1\/vault\/([^/]+)$/);
    if (!match) {
      return new Response("Not found", { status: 404, headers: corsHeaders });
    }

    const id = decodeURIComponent(match[1]).toUpperCase().replace(/[^A-Z0-9]/g, "");
    if (id.length < 12 || id.length > 48) {
      return new Response("Bad id", { status: 400, headers: corsHeaders });
    }

    const key = `vault:${id}`;

    if (request.method === "GET") {
      const value = await env.VAULT_KV.get(key);
      if (!value) {
        return new Response("Not found", { status: 404, headers: corsHeaders });
      }
      return new Response(value, {
        status: 200,
        headers: { ...corsHeaders, "content-type": "application/json; charset=utf-8" },
      });
    }

    if (request.method === "PUT") {
      const contentType = request.headers.get("content-type") || "";
      if (!contentType.toLowerCase().includes("application/json")) {
        return new Response("Unsupported content-type", { status: 415, headers: corsHeaders });
      }

      const body = await request.arrayBuffer();
      if (body.byteLength > 200_000) {
        return new Response("Payload too large", { status: 413, headers: corsHeaders });
      }

      const text = new TextDecoder().decode(body);
      try {
        const json = JSON.parse(text);
        if (!json?.salt || !json?.enc?.iv || !json?.enc?.data) {
          return new Response("Bad payload", { status: 400, headers: corsHeaders });
        }
      } catch {
        return new Response("Bad payload", { status: 400, headers: corsHeaders });
      }

      await env.VAULT_KV.put(key, text, { expirationTtl: 60 * 60 * 24 * 365 });
      return new Response("OK", { status: 200, headers: corsHeaders });
    }

    return new Response("Method not allowed", { status: 405, headers: corsHeaders });
  },
};
