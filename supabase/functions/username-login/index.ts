
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.58.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  if (req.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  try {
    const { username, password } = await req.json();
    const cleanUsername = String(username ?? "").trim().toLowerCase();

    if (
      !/^[a-z0-9_]{3,20}$/.test(cleanUsername) ||
      typeof password !== "string" ||
      password.length < 8
    ) {
      return json({ error: "Invalid username or password" }, 400);
    }

    const url = Deno.env.get("SUPABASE_URL");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");

    if (!url || !serviceKey || !anonKey) {
      console.error("Missing Supabase secrets");
      return json({ error: "Authentication service is not configured" }, 500);
    }

    const admin = createClient(url, serviceKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    });

    const { data: profile, error: profileError } = await admin
      .from("profiles")
      .select("id")
      .eq("username", cleanUsername)
      .maybeSingle();

    if (profileError) {
      console.error(profileError.message);
      return json({ error: "Unable to sign in right now" }, 500);
    }

    if (!profile) {
      return json({ error: "Invalid username or password" }, 401);
    }

    const { data: userData, error: userError } =
      await admin.auth.admin.getUserById(profile.id);

    const email = userData?.user?.email;

    if (userError || !email) {
      console.error(userError?.message);
      return json({ error: "Invalid username or password" }, 401);
    }

    const publicClient = createClient(url, anonKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    });

    const { data: authData, error: authError } =
      await publicClient.auth.signInWithPassword({
        email,
        password,
      });

    if (authError || !authData.session) {
      return json({ error: "Invalid username or password" }, 401);
    }

    return json({
      session: authData.session,
      user: authData.user,
    });
  } catch (error) {
    console.error("Username login failed:", error);
    return json({ error: "Invalid request" }, 400);
  }
});
