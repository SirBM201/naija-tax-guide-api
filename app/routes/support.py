"use client";

import React, { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import AppShell, {
  shellButtonPrimary,
  shellButtonSecondary,
} from "@/components/app-shell";
import WorkspaceSectionCard from "@/components/workspace-section-card";
import {
  Banner,
  MetricCard,
  appInputStyle,
  appSelectStyle,
  appTextareaStyle,
  formatDate,
} from "@/components/ui";
import { CardsGrid, SectionStack } from "@/components/page-layout";
import { useWorkspaceState } from "@/hooks/useWorkspaceState";
import { buildWorkspaceAlerts } from "@/lib/workspace-alerts";

type SupportFormState = {
  category: string;
  priority: string;
  subject: string;
  message: string;
};

type LatestTicket = {
  ticket_id: string;
  status: string;
  category: string;
  priority: string;
  subject: string;
  created_at?: string;
  updated_at?: string;
};

function safeText(value: unknown, fallback = "—"): string {
  const text =
    typeof value === "string"
      ? value.trim()
      : value == null
      ? ""
      : String(value).trim();
  return text || fallback;
}

function truthyValue(value: unknown): boolean {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value > 0;
  if (typeof value === "string") {
    const raw = value.trim().toLowerCase();
    return ["1", "true", "yes", "active", "paid", "enabled", "linked"].includes(raw);
  }
  return false;
}

function infoBoxStyle(): React.CSSProperties {
  return {
    border: "1px solid var(--border)",
    borderRadius: 18,
    background: "var(--surface)",
    padding: 16,
    display: "grid",
    gap: 6,
  };
}

function pageGridStyle(): React.CSSProperties {
  return {
    display: "grid",
    gridTemplateColumns: "minmax(0, 1.45fr) minmax(320px, 0.95fr)",
    gap: 18,
    alignItems: "start",
  };
}

function checklistStyle(): React.CSSProperties {
  return {
    display: "grid",
    gap: 12,
    color: "var(--text)",
    fontSize: 15,
    lineHeight: 1.8,
  };
}

export default function SupportPage() {
  const router = useRouter();
  const { user, token } = useAuth();

  const {
    profile,
    usage,
    subscription,
    channelLinks,
    billing,
    credits,
  } = useWorkspaceState();

  const alerts = useMemo(
    () =>
      buildWorkspaceAlerts({
        profile,
        usage,
        subscription,
        channelLinks,
        billing,
        credits,
      }),
    [profile, usage, subscription, channelLinks, billing, credits]
  );

  const primaryAlert =
    alerts.find(
      (alert) =>
        /billing|subscription|credit|channel|support|login/i.test(alert.title) ||
        /billing|subscription|credit|channel|support|login/i.test(alert.subtitle)
    ) || null;

  const accountEmail = safeText(
    profile?.email || user?.email || billing?.checkout_email || "Not visible"
  );
  const accountName = safeText(
    profile?.full_name || profile?.first_name || user?.email || "Workspace user"
  );
  const planName = safeText(
    subscription?.plan_name ||
      billing?.plan_name ||
      subscription?.plan_code ||
      billing?.plan_code ||
      "No active plan"
  );
  const planStatus = safeText(subscription?.status || billing?.status || "Unknown");
  const activeNow = truthyValue(
    subscription?.active ||
      billing?.active ||
      planStatus.toLowerCase() === "active"
  );

  const creditBalance = Number(credits?.balance ?? 0);

  const whatsappLinked = truthyValue(
    channelLinks?.whatsapp_linked || channelLinks?.whatsapp?.linked
  );
  const telegramLinked = truthyValue(
    channelLinks?.telegram_linked || channelLinks?.telegram?.linked
  );

  const channelState =
    whatsappLinked && telegramLinked
      ? "WhatsApp + Telegram linked"
      : whatsappLinked
      ? "WhatsApp linked"
      : telegramLinked
      ? "Telegram linked"
      : "No linked channel";

  const [form, setForm] = useState<SupportFormState>({
    category: "general",
    priority: "normal",
    subject: "",
    message: "",
  });

  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [loadingLatest, setLoadingLatest] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [latestTicket, setLatestTicket] = useState<LatestTicket | null>(null);

  function setField<K extends keyof SupportFormState>(key: K, value: SupportFormState[K]) {
    setForm((prev) => ({ ...prev, [key]: value }));
    setNotice("");
    setError("");
  }

  async function loadLatestTicket() {
    if (!token) {
      setLatestTicket(null);
      return;
    }

    setLoadingLatest(true);
    try {
      const response = await fetch("/api/web/support/latest", {
        headers: {
          Authorization: `Bearer ${token}`,
        },
        cache: "no-store",
      });

      const data = await response.json().catch(() => ({}));

      if (response.ok && data?.ok && data?.ticket) {
        setLatestTicket(data.ticket as LatestTicket);
      } else {
        setLatestTicket(null);
      }
    } catch {
      setLatestTicket(null);
    } finally {
      setLoadingLatest(false);
    }
  }

  useEffect(() => {
    loadLatestTicket();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  async function handleSubmit() {
    if (!token) {
      setError("You must be logged in before submitting a support request.");
      return;
    }

    if (!form.subject.trim() || !form.message.trim()) {
      setError("Please provide both a support subject and a clear description of the issue.");
      setNotice("");
      return;
    }

    setSubmitting(true);
    setNotice("");
    setError("");

    try {
      const response = await fetch("/api/web/support", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          fullName: accountName,
          contactEmail: accountEmail === "Not visible" ? "" : accountEmail,
          issueType: form.category,
          priority: form.priority,
          channel: "web",
          subject: form.subject.trim(),
          message: form.message.trim(),
          planName: planName,
          creditBalance: creditBalance,
          channelState: channelState,
        }),
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok || !data?.ok) {
        throw new Error(data?.message || data?.error || "Support request could not be submitted.");
      }

      setNotice(
        `Support request submitted successfully. Ticket ID: ${data?.ticket?.ticket_id || "Not shown"}`
      );

      setForm({
        category: "general",
        priority: "normal",
        subject: "",
        message: "",
      });

      await loadLatestTicket();
    } catch (err: any) {
      setError(err?.message || "Support request could not be submitted.");
    } finally {
      setSubmitting(false);
    }
  }

  function handleClear() {
    setForm({
      category: "general",
      priority: "normal",
      subject: "",
      message: "",
    });
    setNotice("");
    setError("");
  }

  return (
    <AppShell
      title="Support"
      subtitle="Report billing, credits, linking, login, or technical issues from one clear support center."
      actions={
        <>
          <button onClick={() => router.push("/help")} style={shellButtonPrimary()}>
            Open Help
          </button>
          <button onClick={() => router.push("/dashboard")} style={shellButtonSecondary()}>
            Back to Dashboard
          </button>
        </>
      }
    >
      <SectionStack>
        {primaryAlert ? (
          <Banner
            tone={primaryAlert.tone}
            title={primaryAlert.title}
            subtitle={primaryAlert.subtitle}
          />
        ) : null}

        {notice ? (
          <Banner tone="good" title="Support request submitted" subtitle={notice} />
        ) : null}

        {error ? (
          <Banner tone="danger" title="Support request issue" subtitle={error} />
        ) : null}

        <WorkspaceSectionCard
          title="Support center"
          subtitle="Use this page to submit a clear support request together with the visible account context that may help review it faster."
        >
          <div style={pageGridStyle()}>
            <div style={{ display: "grid", gap: 18 }}>
              <div style={infoBoxStyle()}>
                <div style={{ fontSize: 18, fontWeight: 900, color: "var(--text)" }}>
                  Open a support request
                </div>
                <div style={{ color: "var(--text-muted)", lineHeight: 1.7 }}>
                  Choose the issue type, set the priority, and explain clearly what happened.
                </div>
              </div>

              <div style={{ display: "grid", gap: 14 }}>
                <select
                  value={form.category}
                  onChange={(event) => setField("category", event.target.value)}
                  style={appSelectStyle()}
                >
                  <option value="general">Issue type: General support</option>
                  <option value="billing">Issue type: Billing or subscription</option>
                  <option value="credits">Issue type: Credits or access</option>
                  <option value="channels">Issue type: WhatsApp or Telegram linking</option>
                  <option value="login">Issue type: Login or authentication</option>
                  <option value="technical">Issue type: Technical issue</option>
                </select>

                <select
                  value={form.priority}
                  onChange={(event) => setField("priority", event.target.value)}
                  style={appSelectStyle()}
                >
                  <option value="normal">Priority: Normal</option>
                  <option value="high">Priority: High</option>
                  <option value="urgent">Priority: Urgent</option>
                </select>

                <input
                  value={form.subject}
                  onChange={(event) => setField("subject", event.target.value)}
                  placeholder="Support subject"
                  style={appInputStyle()}
                />

                <textarea
                  value={form.message}
                  onChange={(event) => setField("message", event.target.value)}
                  placeholder="Describe the issue clearly. Include what happened, what you expected, and what you already checked."
                  rows={9}
                  style={appTextareaStyle()}
                />

                <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                  <button
                    onClick={handleSubmit}
                    disabled={submitting}
                    style={{
                      ...shellButtonPrimary(),
                      opacity: submitting ? 0.7 : 1,
                      cursor: submitting ? "not-allowed" : "pointer",
                    }}
                  >
                    {submitting ? "Submitting..." : "Submit Support Request"}
                  </button>

                  <button onClick={handleClear} style={shellButtonSecondary()}>
                    Clear Form
                  </button>
                </div>
              </div>
            </div>

            <div style={{ display: "grid", gap: 18 }}>
              <div style={infoBoxStyle()}>
                <div style={{ fontSize: 18, fontWeight: 900, color: "var(--text)" }}>
                  Visible account context
                </div>
                <div style={{ color: "var(--text-muted)", lineHeight: 1.7 }}>
                  This summary helps support understand the likely source of the issue without needing unrelated dashboard details.
                </div>
              </div>

              <CardsGrid min={220}>
                <MetricCard
                  label="Account Email"
                  value={accountEmail}
                  helper="Visible email currently associated with the workspace."
                />
                <MetricCard
                  label="Current Plan"
                  value={planName}
                  tone={activeNow ? "good" : "warn"}
                  helper={`Status: ${planStatus}`}
                />
                <MetricCard
                  label="Credits"
                  value={String(creditBalance)}
                  tone={creditBalance > 0 ? "good" : "warn"}
                  helper="Visible AI credit balance at the time of review."
                />
                <MetricCard
                  label="Channel State"
                  value={channelState}
                  helper="Visible WhatsApp and Telegram linking state."
                />
              </CardsGrid>

              <div style={infoBoxStyle()}>
                <div style={{ fontSize: 18, fontWeight: 900, color: "var(--text)" }}>
                  Latest ticket
                </div>
                <div style={{ color: "var(--text-muted)", lineHeight: 1.7 }}>
                  The most recent support request saved for this account.
                </div>
              </div>

              {loadingLatest ? (
                <Banner tone="default" title="Loading latest ticket" subtitle="Please wait..." />
              ) : latestTicket ? (
                <CardsGrid min={220}>
                  <MetricCard
                    label="Ticket ID"
                    value={latestTicket.ticket_id}
                    helper="Latest saved support ticket reference."
                  />
                  <MetricCard
                    label="Status"
                    value={latestTicket.status}
                    tone={latestTicket.status.toLowerCase() === "open" ? "warn" : "good"}
                    helper="Current saved support request state."
                  />
                  <MetricCard
                    label="Last Updated"
                    value={latestTicket.updated_at ? formatDate(latestTicket.updated_at) : "Not shown"}
                    helper="Latest saved update time."
                  />
                  <MetricCard
                    label="Issue Type"
                    value={latestTicket.category}
                    helper="Category attached to the latest saved request."
                  />
                </CardsGrid>
              ) : (
                <Banner
                  tone="default"
                  title="No ticket yet"
                  subtitle="Your latest saved support ticket will appear here after submission."
                />
              )}
            </div>
          </div>
        </WorkspaceSectionCard>

        <WorkspaceSectionCard
          title="Before submitting"
          subtitle="Only the most relevant checks before you open a support request."
        >
          <div
            style={{
              display: "grid",
              gap: 12,
              color: "var(--text)",
              fontSize: 15,
              lineHeight: 1.8,
            }}
          >
            <div style={infoBoxStyle()}>
              Check Billing if the issue is about subscription status, renewal, or plan access.
            </div>
            <div style={infoBoxStyle()}>
              Check Credits if the assistant stops answering or access feels unexpectedly limited.
            </div>
            <div style={infoBoxStyle()}>
              Check Channels if the issue involves WhatsApp or Telegram linking behavior.
            </div>
            <div style={infoBoxStyle()}>
              Use Help first if you are unsure whether the issue is billing, credits, channels, or normal app behavior.
            </div>
          </div>
        </WorkspaceSectionCard>
      </SectionStack>
    </AppShell>
  );
}

