"use client";

import React, { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import AppShell from "@/components/app-shell";
import WorkspaceActionBar from "@/components/workspace-action-bar";
import WorkspaceSectionCard from "@/components/workspace-section-card";
import {
  Banner,
  MetricCard,
  ShortcutCard,
  appInputStyle,
  appSelectStyle,
  formatDate,
} from "@/components/ui";
import {
  CardsGrid,
  SectionStack,
  TwoColumnSection,
} from "@/components/page-layout";
import WorkspaceOverviewMetrics from "@/components/workspace-overview-metrics";
import { useWorkspaceState } from "@/hooks/useWorkspaceState";
import { buildWorkspaceAlerts } from "@/lib/workspace-alerts";
import { getHistoryItems, type HistoryItem as LocalHistoryItem } from "@/lib/history-storage";

type BackendHistoryItem = {
  id?: string;
  account_id?: string;
  question?: string;
  answer?: string;
  lang?: string;
  source?: string;
  from_cache?: boolean;
  canonical_key?: string | null;
  normalized_question?: string | null;
  plan_code?: string | null;
  credits_consumed?: number;
  usage_charged?: boolean;
  channel?: string | null;
  created_at?: string;
  updated_at?: string;
};

type DisplayHistoryItem = {
  id: string;
  question: string;
  answer: string;
  language: string;
  source: string;
  created_at: string;
  from_cache?: boolean;
};

type HistoryApiResponse = {
  ok: boolean;
  items?: BackendHistoryItem[];
  count?: number;
  error?: string;
  message?: string;
  root_cause?: string;
};

function resolveApiBase(): string {
  const envBase =
    (process.env.NEXT_PUBLIC_API_BASE || process.env.NEXT_PUBLIC_API_URL || "").trim();

  if (envBase) {
    return envBase.replace(/\/+$/, "");
  }

  if (typeof window !== "undefined") {
    return window.location.origin.replace(/\/+$/, "");
  }

  return "";
}

function buildAuthHeaders(): Record<string, string> {
  const headers: Record<string, string> = {};

  if (typeof window !== "undefined") {
    const token = (window.localStorage.getItem("nt_access_token") || "").trim();
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
  }

  return headers;
}

async function fetchHistoryItems(params?: {
  source?: string;
  q?: string;
  limit?: number;
}): Promise<HistoryApiResponse> {
  const apiBase = resolveApiBase();
  const url = new URL(`${apiBase}/api/history`);

  if (params?.source && params.source !== "all") {
    url.searchParams.set("source", params.source);
  }
  if (params?.q) {
    url.searchParams.set("q", params.q);
  }
  url.searchParams.set("limit", String(params?.limit || 50));

  const res = await fetch(url.toString(), {
    method: "GET",
    headers: buildAuthHeaders(),
    credentials: "include",
  });

  let data: HistoryApiResponse | null = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }

  if (!res.ok) {
    return data || { ok: false, error: "history_fetch_failed", message: `Failed with status ${res.status}` };
  }

  return data || { ok: false, error: "invalid_response", message: "Invalid history response." };
}

function truncateText(value: string, max = 180) {
  const text = String(value || "").trim();
  if (text.length <= max) return text;
  return `${text.slice(0, max)}...`;
}

function sourceLabel(source?: string) {
  const v = String(source || "").toLowerCase();
  if (v === "web") return "Web";
  if (v === "whatsapp") return "WhatsApp";
  if (v === "telegram") return "Telegram";
  if (v === "cache") return "Cache";
  if (v === "ai") return "AI";
  return "Unknown";
}

function languageLabel(language?: string) {
  const v = String(language || "").trim();
  return v || "English";
}

function toneFromHistoryCount(count: number): "good" | "warn" | "default" {
  if (count >= 5) return "good";
  if (count >= 1) return "warn";
  return "default";
}

function mapBackendItem(row: BackendHistoryItem, index: number): DisplayHistoryItem {
  return {
    id: String(row.id || `${row.created_at || "history"}-${index}`),
    question: String(row.question || ""),
    answer: String(row.answer || ""),
    language: String(row.lang || "en"),
    source: String(row.source || "web"),
    created_at: String(row.created_at || row.updated_at || ""),
    from_cache: Boolean(row.from_cache),
  };
}

function mapLocalItem(row: LocalHistoryItem, index: number): DisplayHistoryItem {
  return {
    id: String((row as any).id || `${row.created_at || "local"}-${index}`),
    question: String(row.question || ""),
    answer: String(row.answer || ""),
    language: String(row.language || "English"),
    source: String(row.source || "web"),
    created_at: String(row.created_at || ""),
  };
}

function HistoryItemCard({
  item,
  expanded,
  onToggle,
}: {
  item: DisplayHistoryItem;
  expanded: boolean;
  onToggle: () => void;
}) {
  return (
    <div
      style={{
        borderRadius: 22,
        border: "1px solid var(--border)",
        background: "var(--surface)",
        padding: 18,
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          gap: 12,
          alignItems: "flex-start",
          flexWrap: "wrap",
        }}
      >
        <div style={{ minWidth: 0 }}>
          <div
            style={{
              color: "var(--gold)",
              fontWeight: 900,
              fontSize: 12,
              textTransform: "uppercase",
              letterSpacing: 0.45,
            }}
          >
            {sourceLabel(item.source)} • {languageLabel(item.language)}
          </div>

          <div
            style={{
              marginTop: 10,
              color: "var(--text)",
              fontWeight: 900,
              fontSize: 18,
              lineHeight: 1.5,
              wordBreak: "break-word",
            }}
          >
            {expanded ? String(item.question || "Untitled question") : truncateText(String(item.question || "Untitled question"), 140)}
          </div>
        </div>

        <div
          style={{
            color: "var(--text-faint)",
            fontSize: 13,
            whiteSpace: "nowrap",
          }}
        >
          {formatDate(item.created_at)}
        </div>
      </div>

      <div
        style={{
          marginTop: 16,
          borderRadius: 18,
          border: "1px solid var(--border)",
          background: "var(--surface-soft)",
          padding: 16,
        }}
      >
        <div
          style={{
            color: "var(--text-faint)",
            fontSize: 12,
            fontWeight: 800,
            textTransform: "uppercase",
            letterSpacing: 0.35,
          }}
        >
          Answer
        </div>
        <div
          style={{
            marginTop: 10,
            color: "var(--text-muted)",
            lineHeight: 1.75,
            fontSize: 14,
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
          }}
        >
          {expanded ? String(item.answer || "No saved answer.") : truncateText(String(item.answer || "No saved answer."), 320)}
        </div>
      </div>

      <div
        style={{
          marginTop: 14,
          display: "flex",
          justifyContent: "space-between",
          gap: 12,
          alignItems: "center",
          flexWrap: "wrap",
        }}
      >
        <div
          style={{
            color: "var(--text-faint)",
            fontSize: 13,
            lineHeight: 1.5,
          }}
        >
          Saved item available for continuity, follow-up, and user review.
        </div>

        <button
          onClick={onToggle}
          style={{
            padding: "12px 16px",
            borderRadius: 14,
            border: "1px solid var(--border-strong)",
            background: "var(--button-bg)",
            color: "var(--text)",
            fontWeight: 900,
            cursor: "pointer",
          }}
        >
          {expanded ? "Show Less" : "Open Full Item"}
        </button>
      </div>
    </div>
  );
}

export default function HistoryPage() {
  const router = useRouter();
  const { refreshSession, logout } = useAuth();

  const [historyItems, setHistoryItems] = useState<DisplayHistoryItem[]>([]);
  const [search, setSearch] = useState("");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [historyNotice, setHistoryNotice] = useState<{
    title: string;
    message: string;
    tone: "good" | "warn" | "danger" | "default";
  } | null>(null);

  const {
    busy,
    status,
    load,
    accountId,
    activeNow,
    planCode,
    creditBalance,
    dailyUsage,
    dailyLimit,
    expiresAt,
    pendingPlanCode,
    pendingStartsAt,
  } = useWorkspaceState({
    refreshSession,
    autoLoad: false,
    includeAccount: true,
    includeBilling: true,
    includeDebug: true,
    loadingMessage: "Loading history workspace...",
  });

  const loadHistoryWorkspace = async (message = "Loading history workspace...") => {
    await load(message);

    try {
      setLoadingHistory(true);
      setHistoryNotice(null);

      const result = await fetchHistoryItems({
        source: sourceFilter,
        q: search.trim(),
        limit: 50,
      });

      if (result.ok && Array.isArray(result.items)) {
        setHistoryItems(result.items.map(mapBackendItem));
        return;
      }

      const localItems = getHistoryItems().map(mapLocalItem);
      setHistoryItems(localItems);

      if (result.error) {
        setHistoryNotice({
          title: "Backend history unavailable",
          message:
            result.message ||
            result.root_cause ||
            "Falling back to local history storage because backend history is not yet fully available.",
          tone: "warn",
        });
      }
    } catch (err: any) {
      const localItems = getHistoryItems().map(mapLocalItem);
      setHistoryItems(localItems);

      setHistoryNotice({
        title: "History fallback in use",
        message:
          err?.message ||
          "A backend history error occurred, so local history storage is being shown instead.",
        tone: "warn",
      });
    } finally {
      setLoadingHistory(false);
    }
  };

  useEffect(() => {
    loadHistoryWorkspace();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const alerts = buildWorkspaceAlerts({
    activeNow,
    creditBalance,
    dailyUsage,
    dailyLimit,
    pendingPlanCode,
    pendingStartsAt,
    status,
    includeStatusAlert: true,
    statusTitle: "Current history workspace status",
  });

  const filteredItems = useMemo(() => {
    const term = search.trim().toLowerCase();

    return historyItems.filter((item) => {
      const matchesSource =
        sourceFilter === "all"
          ? true
          : String(item.source || "").toLowerCase() === sourceFilter;

      if (!matchesSource) return false;

      if (!term) return true;

      const question = String(item.question || "").toLowerCase();
      const answer = String(item.answer || "").toLowerCase();
      const language = String(item.language || "").toLowerCase();
      const source = String(item.source || "").toLowerCase();

      return (
        question.includes(term) ||
        answer.includes(term) ||
        language.includes(term) ||
        source.includes(term)
      );
    });
  }, [historyItems, search, sourceFilter]);

  const webCount = historyItems.filter(
    (item) => String(item.source || "").toLowerCase() === "web"
  ).length;

  const whatsappCount = historyItems.filter(
    (item) => String(item.source || "").toLowerCase() === "whatsapp"
  ).length;

  const telegramCount = historyItems.filter(
    (item) => String(item.source || "").toLowerCase() === "telegram"
  ).length;

  const newestItem = historyItems[0];
  const oldestItem = historyItems[historyItems.length - 1];

  return (
    <AppShell
      title="History"
      subtitle="Review saved tax questions and previous AI answers so users can continue work without losing continuity or repeating earlier requests."
      actions={
        <WorkspaceActionBar
          items={[
            { label: "Ask Tax AI", href: "/ask", tone: "primary" },
            { label: "Credits", href: "/credits", tone: "secondary" },
            {
              label: "Refresh",
              onClick: () => loadHistoryWorkspace("Refreshing history workspace..."),
              tone: "secondary",
              disabled: busy || loadingHistory,
            },
            {
              label: "Logout",
              onClick: logout,
              tone: "danger",
              disabled: busy || loadingHistory,
            },
          ]}
        />
      }
    >
      <SectionStack>
        {historyNotice ? (
          <Banner
            title={historyNotice.title}
            message={historyNotice.message}
            tone={historyNotice.tone}
          />
        ) : null}

        {alerts.map((alert) => (
          <Banner
            key={alert.key}
            title={alert.title}
            message={alert.message}
            tone={alert.tone}
          />
        ))}

        <WorkspaceOverviewMetrics
          mode="dashboard"
          accountId={accountId}
          activeNow={activeNow}
          planCode={planCode}
          creditBalance={creditBalance}
          dailyUsage={dailyUsage}
          dailyLimit={dailyLimit}
          expiresAt={expiresAt}
        />

        <CardsGrid min={220}>
          <MetricCard
            label="Saved Items"
            value={String(historyItems.length)}
            tone={toneFromHistoryCount(historyItems.length)}
            helper="Total visible question-answer items currently saved for this workspace."
          />
          <MetricCard
            label="Filtered Results"
            value={String(filteredItems.length)}
            tone={filteredItems.length > 0 ? "good" : "warn"}
            helper="Visible results after current search and source filter are applied."
          />
          <MetricCard
            label="Newest Item"
            value={newestItem ? formatDate(newestItem.created_at) : "—"}
            tone={newestItem ? "good" : "default"}
            helper="Most recent saved entry currently visible in history."
          />
          <MetricCard
            label="Oldest Item"
            value={oldestItem ? formatDate(oldestItem.created_at) : "—"}
            tone={oldestItem ? "default" : "warn"}
            helper="Earliest visible entry still available in history."
          />
        </CardsGrid>

        <TwoColumnSection leftRatio={1.08} rightRatio={0.92}>
          <WorkspaceSectionCard
            title="History Search"
            subtitle="Find previous questions quickly by keyword or channel source."
          >
            <div style={{ display: "grid", gap: 14 }}>
              <div style={{ display: "grid", gap: 8 }}>
                <div
                  style={{
                    color: "var(--text)",
                    fontWeight: 800,
                    fontSize: 14,
                  }}
                >
                  Search saved history
                </div>
                <input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search question text, answer text, source, or language..."
                  style={appInputStyle}
                />
              </div>

              <div style={{ display: "grid", gap: 8 }}>
                <div
                  style={{
                    color: "var(--text)",
                    fontWeight: 800,
                    fontSize: 14,
                  }}
                >
                  Filter by source
                </div>
                <select
                  value={sourceFilter}
                  onChange={(e) => setSourceFilter(e.target.value)}
                  style={appSelectStyle}
                >
                  <option value="all">All Sources</option>
                  <option value="web">Web</option>
                  <option value="whatsapp">WhatsApp</option>
                  <option value="telegram">Telegram</option>
                  <option value="ai">AI</option>
                  <option value="cache">Cache</option>
                </select>
              </div>

              <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                <WorkspaceActionBar
                  items={[
                    {
                      label: loadingHistory ? "Searching..." : "Apply Search",
                      onClick: () => loadHistoryWorkspace("Refreshing filtered history..."),
                      tone: "primary",
                      disabled: loadingHistory || busy,
                    },
                  ]}
                />
              </div>

              <div
                style={{
                  borderRadius: 18,
                  border: "1px solid var(--border)",
                  background: "var(--surface)",
                  padding: 16,
                  color: "var(--text-muted)",
                  lineHeight: 1.75,
                  fontSize: 14,
                }}
              >
                History is part of user continuity. It should help users return to previous tax guidance, compare earlier answers, and continue work without retyping the same question again.
              </div>
            </div>
          </WorkspaceSectionCard>

          <WorkspaceSectionCard
            title="History Breakdown"
            subtitle="Quick operational view of where saved items came from."
          >
            <CardsGrid min={180}>
              <MetricCard
                label="Web"
                value={String(webCount)}
                tone={webCount > 0 ? "good" : "default"}
                helper="Items saved from the web workspace."
              />
              <MetricCard
                label="WhatsApp"
                value={String(whatsappCount)}
                tone={whatsappCount > 0 ? "good" : "default"}
                helper="Items saved from WhatsApp usage."
              />
              <MetricCard
                label="Telegram"
                value={String(telegramCount)}
                tone={telegramCount > 0 ? "good" : "default"}
                helper="Items saved from Telegram usage."
              />
            </CardsGrid>

            <MetricCard
              label="Continuity State"
              value={historyItems.length > 0 ? "Available" : "Empty"}
              tone={historyItems.length > 0 ? "good" : "warn"}
              helper="Whether the user currently has any saved history to revisit."
            />
          </WorkspaceSectionCard>
        </TwoColumnSection>

        <WorkspaceSectionCard
          title="Saved Questions and Answers"
          subtitle="Open previous records to continue work with confidence and continuity."
        >
          {filteredItems.length > 0 ? (
            <div style={{ display: "grid", gap: 16 }}>
              {filteredItems.map((item) => {
                const itemId = String(item.id);

                return (
                  <HistoryItemCard
                    key={itemId}
                    item={item}
                    expanded={expandedId === itemId}
                    onToggle={() =>
                      setExpandedId((current) => (current === itemId ? null : itemId))
                    }
                  />
                );
              })}
            </div>
          ) : (
            <Banner
              title="No matching history found"
              message={
                historyItems.length > 0
                  ? "No saved items match your current search or source filter. Adjust the filters and try again."
                  : "No question history is visible yet. Once successful tax questions are saved, they will appear here for future review."
              }
              tone={historyItems.length > 0 ? "warn" : "default"}
            />
          )}
        </WorkspaceSectionCard>

        <WorkspaceSectionCard
          title="Recommended Actions"
          subtitle="Use history together with other workspace tools to reduce repeated work."
        >
          <CardsGrid min={240}>
            <ShortcutCard
              title="Ask Tax AI"
              subtitle={
                !activeNow
                  ? "Your account may need active paid access before new questions can continue."
                  : creditBalance <= 0
                  ? "Your visible credits are exhausted. Review Credits or Plans before continuing."
                  : "Ask a new tax question when saved history is no longer enough."
              }
              tone={!activeNow ? "warn" : creditBalance <= 0 ? "danger" : "good"}
              onClick={() => router.push("/ask")}
            />

            <ShortcutCard
              title="Credits"
              subtitle="Review balance and daily usage before deciding whether to continue with fresh AI requests."
              tone={creditBalance <= 3 ? "warn" : "default"}
              onClick={() => router.push("/credits")}
            />

            <ShortcutCard
              title="Billing"
              subtitle="Check subscription condition, expiry, and billing readiness if access needs attention."
              tone={!activeNow ? "warn" : "default"}
              onClick={() => router.push("/billing")}
            />

            <ShortcutCard
              title="Help Center"
              subtitle="Open guided help if the user needs assistance interpreting results or workspace behavior."
              tone="default"
              onClick={() => router.push("/help")}
            />
          </CardsGrid>
        </WorkspaceSectionCard>

        <TwoColumnSection>
          <WorkspaceSectionCard
            title="History Notes"
            subtitle="How this page should function in a real SaaS workflow."
          >
            <div
              style={{
                display: "grid",
                gap: 10,
                color: "var(--text-muted)",
                fontSize: 14,
                lineHeight: 1.75,
              }}
            >
              <div>1. History should make the product feel continuous, not disposable.</div>
              <div>2. Users should be able to find earlier answers without friction.</div>
              <div>3. Search and source filtering reduce repeated questioning.</div>
              <div>4. Saved answers improve trust because users can revisit prior guidance.</div>
              <div>5. This page is now prepared for real backend-linked continuity.</div>
            </div>
          </WorkspaceSectionCard>

          <WorkspaceSectionCard
            title="Next Best Decision"
            subtitle="Fast summary of what the user should do next."
          >
            <CardsGrid min={220}>
              <MetricCard
                label="Best Immediate Action"
                value={
                  filteredItems.length > 0
                    ? "Review Saved Answers"
                    : historyItems.length > 0
                    ? "Adjust Filters"
                    : "Ask First Question"
                }
                tone={
                  filteredItems.length > 0
                    ? "good"
                    : historyItems.length > 0
                    ? "warn"
                    : "default"
                }
                helper="Most sensible next move based on current visible history."
              />
              <MetricCard
                label="History Utility"
                value={historyItems.length > 0 ? "Useful" : "Not Yet Built"}
                tone={historyItems.length > 0 ? "good" : "warn"}
                helper="Shows whether user continuity is already active in this workspace."
              />
            </CardsGrid>
          </WorkspaceSectionCard>
        </TwoColumnSection>
      </SectionStack>
    </AppShell>
  );
}
