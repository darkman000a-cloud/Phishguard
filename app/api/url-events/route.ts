import { NextRequest } from "next/server";
import { jsonWithCors, handleCorsOptions } from "@/lib/cors";
import { classifyUrl } from "@/lib/detector";
import { db } from "@/lib/db";

export async function OPTIONS() {
  return handleCorsOptions();
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { clientId, clientName, events } = body;

    if (!Array.isArray(events) || events.length === 0) {
      return jsonWithCors({ success: true, acknowledgedIds: [] });
    }

    const acknowledgedIds: string[] = [];

    for (const evt of events) {
      if (!evt.url) continue;

      try {
        let classification = evt.classification;
        let verdict = evt.verdict;
        let score = typeof evt.score === "number" ? evt.score : 0.05;
        let domain = evt.domain;
        let reason = evt.reason || (Array.isArray(evt.reasons) ? evt.reasons.join("; ") : "Extension telemetry");

        if (!classification || !domain) {
          const analyzed = await classifyUrl(evt.url);
          classification = analyzed.verdict;
          verdict = analyzed.action;
          score = analyzed.score;
          domain = analyzed.domain;
          if (!reason || reason === "Extension telemetry") {
            reason = analyzed.reasons.join("; ");
          }
        }

        let safeDomain = domain;
        if (!safeDomain) {
          try {
            const uStr = evt.url.startsWith("http") ? evt.url : `http://${evt.url}`;
            safeDomain = new URL(uStr).hostname.toLowerCase();
          } catch {
            safeDomain = "unknown-domain";
          }
        }

        const eventId = evt.eventId || `evt_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;

        const { wasNew } = await db.recordUrlEvent(
          {
            eventId,
            url: evt.url,
            domain: safeDomain,
            classification,
            verdict: verdict || (classification === "PHISHING" ? "BLOCKED" : classification === "SUSPICIOUS" ? "WARNING" : "ALLOWED"),
            score,
            reason,
            clientId: clientId || evt.clientId || "unknown-client",
            clientName: clientName || evt.clientName || "Unknown Workstation",
            source: evt.source || "extension-telemetry",
            ruleTriggered: evt.ruleTriggered ?? Boolean(evt.ruleMatch),
            ruleType: evt.ruleType || (classification === "PHISHING" && evt.ruleMatch ? "PHISHING" : null)
          },
          evt.observedAt || evt.timestamp
        );

        acknowledgedIds.push(eventId);

        // Avoid duplicate alerts when the same event is retried
        if (wasNew && (classification === "PHISHING" || score >= 0.8)) {
          await db.recordThreatAlert({
            clientId: clientId || evt.clientId || "unknown-client",
            clientName: clientName || evt.clientName || "Unknown Workstation",
            url: evt.url,
            domain: safeDomain,
            score,
            reasons: Array.isArray(evt.reasons) ? evt.reasons : [reason],
            source: evt.source || "extension-telemetry"
          });
        }
      } catch (evtErr) {
        console.warn("Could not process single URL event in batch:", evtErr);
      }
    }

    return jsonWithCors({
      success: true,
      acknowledgedIds
    });
  } catch (err: any) {
    return jsonWithCors({ error: "Failed to process URL events", message: err?.message }, { status: 500 });
  }
}
