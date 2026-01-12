import { NextResponse } from "next/server";

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const reference = String(body?.reference || "").trim();

    if (!reference) {
      return NextResponse.json(
        { ok: false, error: "reference required" },
        { status: 400 }
      );
    }

    const backend = process.env.BACKEND_BASE_URL?.replace(/\/$/, "");
    if (!backend) {
      return NextResponse.json(
        { ok: false, error: "BACKEND_BASE_URL not set" },
        { status: 500 }
      );
    }

    const r = await fetch(`${backend}/paystack/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reference }),
      cache: "no-store",
    });

    const raw = await r.json().catch(() => ({}));

    // Expect backend returns: { ok: true, paid: true/false, ... }
    if (r.ok && raw?.ok) return NextResponse.json(raw, { status: 200 });

    return NextResponse.json(
      { ok: false, error: raw?.error || "verify_failed", detail: raw },
      { status: r.status || 502 }
    );
  } catch (e: any) {
    return NextResponse.json(
      { ok: false, error: e?.message || "Server error" },
      { status: 500 }
    );
  }
}
