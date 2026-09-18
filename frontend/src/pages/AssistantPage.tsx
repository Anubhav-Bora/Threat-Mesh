import { FormEvent, useEffect, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import {
  AlertTriangle,
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
import type {
  AssistantCitation,
  AssistantHistoryItem,
  AssistantMode,
  ChatMessage,
} from "../types";

const suggestions = [
  "Which campaigns have the highest average IOC confidence?",
  "What are the most observed ATT&CK techniques in the last 7 days?",
  "Where is recent infrastructure concentrated?",
  "Explain zero trust in simple terms.",
];

const greeting: ChatMessage = {
  id: "welcome",
  role: "assistant",
  createdAt: new Date().toISOString(),
  content:
    "Ask about ThreatMesh evidence, this project's design, cybersecurity concepts, or any general topic. Auto mode retrieves evidence when your question is about ThreatMesh data and uses general knowledge otherwise.",
};

export default function AssistantPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([greeting]);
  const [question, setQuestion] = useState("");
  const [assistantMode, setAssistantMode] = useState<AssistantMode>("auto");
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
    mutationFn: (input: {
      question: string;
      mode: AssistantMode;
      history: AssistantHistoryItem[];
    }) =>
      threatApi.ask(input.question, {
        mode: input.mode,
        history: input.history,
      }),
    onSuccess: (result) => {
      setMessages((items) => [
        ...items,
        {
          id: `assistant-${Date.now()}`,
          role: "assistant",
          content: result.data.answer,
          createdAt: new Date().toISOString(),
          answerMode: result.data.answerMode,
          citations: result.data.citations,
          retrievedCount: result.data.retrievedCount,
          queryTimeMs: result.data.queryTimeMs,
          includedProvenance: result.data.includedProvenance,
          citationIntegrity: result.data.citationIntegrity,
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
            "The AI service could not complete this request. Try again, or switch between General and Threat data mode if the provider misunderstood the request.",
          createdAt: new Date().toISOString(),
        },
      ]);
    },
  });

  useEffect(() => {
    bottomRef.current?.scrollIntoView({
      behavior: "smooth",
      block: "nearest",
    });
  }, [messages, ask.isPending]);

  const submit = (event?: FormEvent, suggested?: string) => {
    event?.preventDefault();
    const content = (suggested ?? question).trim();
    if (!content || ask.isPending) return;
    const history = messages
      .filter((message) => message.id !== "welcome")
      .slice(-8)
      .map((message) => ({
        role: message.role,
        content: message.content,
      }));
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
    ask.mutate({ question: content, mode: assistantMode, history });
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
            <span>Grounded threat intelligence · general AI assistance</span>
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
                <GroundedAnswer
                  content={message.content}
                  citations={message.citations ?? []}
                  onOpen={(citation) => {
                    const target = citationTarget(citation);
                    if (target) navigate(target);
                  }}
                />
                {message.citations && message.citations.length > 0 && (
                  <div className="citation-block">
                    <span>
                      <Database size={13} />
                      {message.citationIntegrity
                        ? "Server-validated evidence"
                        : "Retrieved demo evidence"}
                    </span>
                    <div>
                      {message.citations.map((citation) => {
                        const target = citationTarget(citation);
                        const content = (
                          <>
                            <i>{citation.kind.slice(0, 1).toUpperCase()}</i>
                            {citation.label}
                            {target && <ArrowRight size={12} />}
                          </>
                        );
                        return target ? (
                          <button
                            key={citation.recordId}
                            type="button"
                            onClick={() => navigate(target)}
                          >
                            {content}
                          </button>
                        ) : (
                          <span
                            className="citation-chip"
                            key={citation.recordId}
                          >
                            {content}
                          </span>
                        );
                      })}
                    </div>
                  </div>
                )}
                {message.retrievedCount !== undefined && (
                  <div className="answer-meta">
                    <span>
                      {message.answerMode === "general" ? (
                        <Sparkles size={12} />
                      ) : (
                        <CheckCircle2 size={12} />
                      )}
                      {message.answerMode === "general"
                        ? "General knowledge · no live records used"
                        : `Grounded in ${message.retrievedCount} retrieved record${message.retrievedCount === 1 ? "" : "s"}`}
                    </span>
                    <span>
                      <Clock3 size={12} />
                      {message.queryTimeMs} ms
                    </span>
                    {message.answerMode !== "general" &&
                      message.includedProvenance && (
                        <span>
                          <Database size={12} />
                          {message.includedProvenance === "demo"
                            ? "Synthetic demo evidence"
                            : message.includedProvenance === "live"
                              ? "Live-feed evidence"
                              : "No evidence included"}
                        </span>
                      )}
                    {message.answerMode !== "general" &&
                      message.citationIntegrity && (
                        <span
                          className={`citation-status citation-status--${message.citationIntegrity.status}`}
                        >
                          {message.citationIntegrity.status === "verified" ? (
                            <ShieldCheck size={12} />
                          ) : message.citationIntegrity.status === "partial" ||
                            message.citationIntegrity.rejectedCount > 0 ? (
                            <AlertTriangle size={12} />
                          ) : (
                            <LockKeyhole size={12} />
                          )}
                          {message.citationIntegrity.status === "verified"
                            ? `${message.citationIntegrity.validatedCount} citation ID${message.citationIntegrity.validatedCount === 1 ? "" : "s"} verified`
                            : message.citationIntegrity.status === "partial"
                              ? message.citationIntegrity.rejectedCount > 0
                                ? `${message.citationIntegrity.validatedCount} valid · ${message.citationIntegrity.rejectedCount} rejected`
                                : `${message.citationIntegrity.validatedCount} valid · citation set mismatch`
                              : message.citationIntegrity.rejectedCount > 0
                                ? `0 valid · ${message.citationIntegrity.rejectedCount} rejected`
                                : "No citation IDs returned"}
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
                  <span>
                    {assistantMode === "general"
                      ? "Thinking…"
                      : "Retrieving context and composing…"}
                  </span>
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
          <div
            className="assistant-mode-switch"
            role="group"
            aria-label="Assistant answer mode"
          >
            {(
              [
                ["auto", "Auto"],
                ["threatmesh", "Threat data"],
                ["general", "General"],
              ] as const
            ).map(([value, label]) => (
              <button
                key={value}
                type="button"
                className={assistantMode === value ? "is-active" : ""}
                aria-pressed={assistantMode === value}
                disabled={ask.isPending}
                onClick={() => setAssistantMode(value)}
              >
                {label}
              </button>
            ))}
          </div>
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
            placeholder={
              assistantMode === "general"
                ? "Ask anything…"
                : assistantMode === "threatmesh"
                  ? "Ask about ThreatMesh evidence or the project…"
                  : "Ask about ThreatMesh or anything else…"
            }
            rows={2}
            aria-label="Question for ThreatMesh"
          />
          <div>
            <span>
              <ShieldCheck size={13} />
              {assistantMode === "general"
                ? "General model knowledge · verify important answers"
                : assistantMode === "threatmesh"
                  ? "Retrieved project context · analyst review required"
                  : "Automatic routing · mode shown on every answer"}
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
          <span className="eyebrow">How answers are built</span>
          <h2>Hybrid assistant</h2>
          <ol>
            <li>
              <span>
                <Search size={17} />
              </span>
              <div>
                <strong>Choose an answer mode</strong>
                <small>Auto, Threat data, or General</small>
              </div>
            </li>
            <li>
              <span>
                <Database size={17} />
              </span>
              <div>
                <strong>Add the right context</strong>
                <small>Project context always; records only when needed</small>
              </div>
            </li>
            <li>
              <span>
                <Braces size={17} />
              </span>
              <div>
                <strong>Protect evidence claims</strong>
                <small>Allow-listed IDs, dates, counts, and provenance</small>
              </div>
            </li>
            <li>
              <span>
                <Sparkles size={17} />
              </span>
              <div>
                <strong>Continue the conversation</strong>
                <small>Up to eight recent messages provide context</small>
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
            <li>Live-data claims require retrieved context</li>
            <li>General answers are visibly labelled</li>
            <li>Displayed citation IDs are server validated</li>
          </ul>
        </section>
        <section className="panel assistant-tips">
          <span className="eyebrow">Query tips</span>
          <p>
            Use Threat data for strict evidence retrieval, General for ordinary
            questions, or Auto to let ThreatMesh choose.
          </p>
          <code>“Show QakBot domains observed this week.”</code>
        </section>
      </aside>
    </div>
  );
}

const referencePattern =
  /(\[[a-z][a-z0-9_-]{1,31}:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\])/gi;

function GroundedAnswer({
  content,
  citations,
  onOpen,
}: {
  content: string;
  citations: AssistantCitation[];
  onOpen: (citation: AssistantCitation) => void;
}) {
  const byRecordId = new Map(
    citations.map((citation, index) => [
      citation.recordId.toLowerCase(),
      { citation, index: index + 1 },
    ]),
  );
  return (
    <p>
      {content.split(referencePattern).map((part, index) => {
        const recordId = part.startsWith("[") ? part.slice(1, -1) : "";
        const match = byRecordId.get(recordId.toLowerCase());
        if (!match) return part;
        const target = citationTarget(match.citation);
        return target ? (
          <button
            className="inline-citation"
            type="button"
            key={`${recordId}-${index}`}
            onClick={() => onOpen(match.citation)}
            aria-label={`Open evidence ${match.citation.label}`}
            title={match.citation.label}
          >
            {match.index}
          </button>
        ) : (
          <span
            className="inline-citation inline-citation--static"
            key={`${recordId}-${index}`}
            title={match.citation.label}
          >
            {match.index}
          </span>
        );
      })}
    </p>
  );
}

function citationTarget(citation: AssistantCitation) {
  const value = encodeURIComponent(citation.id);
  if (citation.kind === "indicator") return `/indicators?ioc=${value}`;
  if (citation.kind === "campaign") return `/campaigns?campaign=${value}`;
  if (citation.kind === "technique") return `/attack?technique=${value}`;
  if (citation.kind === "report") return `/reports?report=${value}`;
  return null;
}
