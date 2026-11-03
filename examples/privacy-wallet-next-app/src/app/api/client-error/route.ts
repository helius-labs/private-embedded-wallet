import { NextResponse } from "next/server";
import { sameRequestOrigin } from "../tvc/request-origin";

export const runtime = "nodejs";

const MAX_REQUEST_BYTES = 16 * 1024;

function optionalString(value: unknown, maximum: number): string | undefined {
  return typeof value === "string" ? value.slice(0, maximum) : undefined;
}

export async function POST(request: Request) {
  try {
    sameRequestOrigin(request);
    const encoded = await request.text();
    if (Buffer.byteLength(encoded) > MAX_REQUEST_BYTES) {
      return NextResponse.json({ error: "ClientErrorReportTooLarge" }, { status: 413 });
    }
    const body = JSON.parse(encoded) as Record<string, unknown>;
    console.error("Client runtime error", {
      operation: optionalString(body.operation, 100),
      name: optionalString(body.name, 100),
      message: optionalString(body.message, 1_000),
      code: optionalString(body.code, 200),
      cause: optionalString(body.cause, 1_000),
      stack: optionalString(body.stack, 8_000),
      digest: optionalString(body.digest, 200),
      path: optionalString(body.path, 500),
    });
    return NextResponse.json({ reported: true });
  } catch {
    return NextResponse.json({ error: "InvalidClientErrorReport" }, { status: 400 });
  }
}
