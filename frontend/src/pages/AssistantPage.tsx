import { FormEvent, useEffect, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import {
  ArrowRight,
  Bot,
  Braces,
  CheckCircle2,
  Clock3,
  Database,
  LockKeyhole,
  Search,
  Send,
  ShieldCheck,
  Sparkles,
  User,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import { threatApi } from "../api/client";
import { Badge } from "../components/UI";
import { useApiMode, useSummary } from "../hooks/useThreatData";
import type { ChatMessage } from "../types";

const suggestions = [
  "Which campaigns have the highest average IOC confidence?",
  "What are the most observed ATT&CK techniques in the last 7 days?",
  "Where is recent infrastructure concentrated?",
  "What are the top malware families this month?",
];

const greeting: ChatMessage = {
  id: "welcome",
  role: "assistant",
  createdAt: new Date().toISOString(),
  content:
    "Ask me about indicators, campaign relationships, ATT&CK techniques, or reporting trends. I retrieve matching ThreatMesh records first, then compose an answer using only that evidence.",
};

export default function AssistantPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([greeting]);
  const [question, setQuestion] = useState("");
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  const mode = useApiMode();
  const summaryQuery = useSummary();
  const corpusMode = summaryQuery.data?.data.corpusMode;
  const corpusLabel =
    mode === "demo"
      ? "Bundled demo corpus"
      : mode === "error"
        ? "API degraded"
        : corpusMode === "demo"
          ? "Seeded demo via API"
          : corpusMode === "mixed"
            ? summaryQuery.data?.data.analysisScope === "live"
              ? "Mixed corpus · live-only retrieval"
              : "Mixed corpus"
            : corpusMode === "live"
              ? "Live feed corpus"
              : "API corpus";
  const ask = useMutation({
    mutationFn: threatApi.ask,
    onSuccess: (result) => {
      setMessages((items) => [
        ...items,
        {
          id: `assistant-${Date.now()}`,
          role: "assistant",
          content: result.data.answer,
          createdAt: new Date().toISOString(),
          citations: result.data.citations,
          retrievedCount: result.data.retrievedCount,
          queryTimeMs: result.data.queryTimeMs,
          includedProvenance: result.data.includedProvenance,
        },
      ]);
    },
    onError: () => {
      setMessages((items) => [
        ...items,
        {
          id: `assistant-${Date.now()}`,
          role: "assistant",
          content:
            "The retrieval service could not complete this query. No answer was generated because ThreatMesh does not respond without evidence.",
          createdAt: new Date().toISOString(),
        },
      ]);
    },
  });

  useEffect(
    () => bottomRef.current?.scrollIntoView({ behavior: "smooth" }),
    [messages, ask.isPending],
  );

  const submit = (event?: FormEvent, suggested?: string) => {
    event?.preventDefault();
    const content = (suggested ?? question).trim();
    if (!content || ask.isPending) return;
    setMessages((items) => [
      ...items,
      {
        id: `user-${Date.now()}`,
        role: "user",
        content,
        createdAt: new Date().toISOString(),
      },
    ]);
    setQuestion("");
    ask.mutate(content);
  };

  return (
    <div className="assistant-layout">
      <section className="panel chat-panel">
        <header className="chat-header">
          <div className="assistant-avatar">
            <Bot size={22} />
            <span className="status-dot status-dot--online" />
          </div>
          <div>
            <strong>ThreatMesh analyst assistant</strong>
            <span>Retrieval first · generation second</span>
          </div>
          <Badge
            tone={
              mode === "demo" || corpusMode === "demo"
                ? "info"
                : mode === "error"
                  ? "critical"
                  : corpusMode === "mixed"
                    ? "warning"
                    : "success"
            }
            dot
          >
            {corpusLabel}
          </Badge>
        </header>
        <div className="chat-stream" aria-live="polite">
          <div className="chat-date">
            <span>Current session</span>
          </div>
          {messages.map((message) => (
            <article
              key={message.id}
              className={`chat-message chat-message--${message.role}`}
            >
              <span className="chat-message__avatar">
                {message.role === "assistant" ? (
                  <Bot size={17} />
                ) : (
                  <User size={17} />
                )}
              </span>
              <div className="chat-message__body">
                <div>
                  <span className="chat-message__author">
                    {message.role === "assistant" ? "ThreatMesh" : "You"}
                  </span>
                  <time>
                    {new Date(message.createdAt).toLocaleTimeString([], {
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
                  </time>
                </div>
                <p>{message.content}</p>
                {message.citations && message.citations.length > 0 && (
                  <div className="citation-block">
                    <span>
                      <Database size={13} />
                      Retrieved evidence
                    </span>
                    <div>
                      {message.citations.map((citation) => (
                        <button
                          key={`${citation.kind}-${citation.id}`}
                          type="button"
                          onClick={() =>
                            navigate(
                              citation.kind === "indicator"
                                ? "/indicators"
                                : citation.kind === "campaign"
                                  ? "/campaigns"
                                  : citation.kind === "technique"
                                    ? "/attack"
                                    : "/reports",
                            )
                          }
                        >
                          <i>{citation.kind.slice(0, 1).toUpperCase()}</i>
                          {citation.label}
                          <ArrowRight size={12} />
                        </button>
                      ))}
                    </div>
                  </div>
                )}
                {message.retrievedCount !== undefined && (
                  <div className="answer-meta">
                    <span>
                      <CheckCircle2 size={12} />
                      Grounded in {message.retrievedCount} retrieved record
                      {message.retrievedCount === 1 ? "" : "s"}
                    </span>
                    <span>
                      <Clock3 size={12} />
                      {message.queryTimeMs} ms
                    </span>
                    {message.includedProvenance && (
                      <span>
                        <Database size={12} />
                        {message.includedProvenance === "demo"
                          ? "Synthetic demo evidence"
                          : message.includedProvenance === "live"
                            ? "Live-feed evidence"
                            : "No evidence included"}
                      </span>
                    )}
                  </div>
                )}
              </div>
            </article>
          ))}
          {ask.isPending && (
            <article className="chat-message chat-message--assistant">
              <span className="chat-message__avatar">
                <Bot size={17} />
              </span>
              <div className="chat-message__body">
                <div>
                  <span className="chat-message__author">ThreatMesh</span>
                </div>
                <div className="retrieval-progress">
                  <span className="typing-dots">
                    <i />
                    <i />
                    <i />
                  </span>
                  <span>Retrieving matching evidence…</span>
                </div>
              </div>
            </article>
          )}
          <div ref={bottomRef} />
        </div>
        <div className="suggestion-row">
          {suggestions.map((item) => (
            <button
              type="button"
              key={item}
              onClick={() => submit(undefined, item)}
              disabled={ask.isPending}
            >
              {item}
            </button>
          ))}
        </div>
        <form className="chat-composer" onSubmit={submit}>
          <textarea
            ref={inputRef}
            value={question}
            onChange={(event) => setQuestion(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                submit();
              }
            }}
            placeholder="Ask a question about your threat data…"
            rows={2}
            aria-label="Question for ThreatMesh"
          />
          <div>
            <span>
              <ShieldCheck size={13} />
              Answers use retrieved records only
            </span>
            <button
              type="submit"
              disabled={!question.trim() || ask.isPending}
              aria-label="Send question"
            >
              <Send size={17} />
            </button>
          </div>
        </form>
      </section>

      <aside className="assistant-sidebar">
        <section className="panel retrieval-card">
          <span className="eyebrow">How this answer is built</span>
          <h2>Evidence pipeline</h2>
          <ol>
            <li>
              <span>
                <Search size={17} />
              </span>
              <div>
                <strong>Interpret the question</strong>
                <small>Constrained intent and entity matching</small>
              </div>
            </li>
            <li>
              <span>
                <Database size={17} />
              </span>
              <div>
                <strong>Retrieve records</strong>
                <small>Postgres facts before model context</small>
              </div>
            </li>
            <li>
              <span>
                <Braces size={17} />
              </span>
              <div>
                <strong>Structure evidence</strong>
                <small>IDs, counts, dates, and provenance</small>
              </div>
            </li>
            <li>
              <span>
                <Sparkles size={17} />
              </span>
              <div>
                <strong>Compose from facts</strong>
                <small>No unsupported data permitted</small>
              </div>
            </li>
          </ol>
        </section>
        <section className="panel guardrail-card">
          <LockKeyhole size={22} />
          <h2>Analyst guardrails</h2>
          <ul>
            <li>No direct database write access</li>
            <li>No autonomous security decisions</li>
            <li>No claims without retrieved evidence</li>
            <li>Citations remain inspectable</li>
          </ul>
        </section>
        <section className="panel assistant-tips">
          <span className="eyebrow">Query tips</span>
          <p>
            Include a time window, IOC type, malware family, or country for a
            narrower retrieval set.
          </p>
          <code>“Show QakBot domains observed this week.”</code>
        </section>
      </aside>
    </div>
  );
}
