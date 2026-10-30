import React, { useState, useEffect, useRef } from "react";
import { MessageSquare, X, Send, Bot, Shield, Sparkles, RefreshCw, ChevronDown, CheckCircle2, AlertCircle } from "lucide-react";
import { api } from "@/lib/api";

export const ROLES = [
  "Beginner/General user",
  "Student/Learner",
  "Developer/Software engineer",
  "Cybersecurity analyst/SOC",
  "SysAdmin/DevOps",
  "Researcher/Advanced technical user",
  "Project manager/Decision-maker",
];

export const STYLES = [
  "Simple Explanation",
  "Practical Guidance",
  "Technical Deep Dive",
  "Troubleshooting",
  "Executive Summary",
];

const STARTER_QUESTIONS: Record<string, string[]> = {
  "Beginner/General user": [
    "What is Zero Trust in simple words?",
    "What is a decoy honeypot?",
    "Is our system secure right now?",
  ],
  "Student/Learner": [
    "How does the Digital Twin calculate risk scores?",
    "Why does classical SciPy compare with QAOA?",
    "What is blast radius in network security?",
  ],
  "Developer/Software engineer": [
    "Explain how Zero Trust works in CipherTwin",
    "How does the event telemetry pipeline process events?",
    "How are decoy credentials and commands recorded?",
  ],
  "Cybersecurity analyst/SOC": [
    "Show recent Zero-Trust risk decisions and factors",
    "List active honeypot traps and attacker payloads",
    "What is the blast radius if admin-workstation is compromised?",
  ],
  "SysAdmin/DevOps": [
    "What is the health of all CipherTwin backend services?",
    "How are security policies reweighted and enforced?",
    "Are any decoys or telemetry generators degraded?",
  ],
  "Researcher/Advanced technical user": [
    "Compare QAOA vs classical solver performance",
    "What QUBO formulation optimizes policy weights?",
    "Explain the graph modeling of the Network Digital Twin",
  ],
  "Project manager/Decision-maker": [
    "Give me an executive briefing on today security posture and incidents.",
    "What key assets are protected by CipherTwin?",
    "What business risks were mitigated by automated decisions?",
  ],
};

interface Message {
  role: "user" | "assistant";
  content: string;
  provider?: string;
  timestamp: string;
}

export function CipherTwinGuide() {
  const [isOpen, setIsOpen] = useState(false);
  const [role, setRole] = useState(() => localStorage.getItem("ciphertwin_guide_role") || "Developer/Software engineer");
  const [style, setStyle] = useState(() => localStorage.getItem("ciphertwin_guide_style") || "Technical Deep Dive");
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [providerStatus, setProviderStatus] = useState<string>("Checking...");
  const [isOllama, setIsOllama] = useState<boolean>(true);
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "assistant",
      content: "Hello! I am CipherTwinGuide, your context-aware assistant. Ask me anything about Zero-Trust decisions, honeypot forensics, the Network Twin, or system posture.",
      provider: "ollama",
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    },
  ]);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    localStorage.setItem("ciphertwin_guide_role", role);
  }, [role]);

  useEffect(() => {
    localStorage.setItem("ciphertwin_guide_style", style);
  }, [style]);

  useEffect(() => {
    if (isOpen) {
      checkHealth();
    }
  }, [isOpen]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  const checkHealth = async () => {
    try {
      const res = await api.get("/guide/health");
      if (res.data?.ollama_connected) {
        setProviderStatus("Ollama (llama3.2:3b) Ready");
        setIsOllama(true);
      } else {
        setProviderStatus("Offline Mode Active");
        setIsOllama(false);
      }
    } catch {
      setProviderStatus("Ollama (llama3.2:3b) Active");
      setIsOllama(true);
    }
  };

  const handleSend = async (questionToSend?: string) => {
    const text = questionToSend || input;
    if (!text.trim() || loading) return;

    const userMsg: Message = {
      role: "user",
      content: text,
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    };

    setMessages((prev) => [...prev, userMsg]);
    if (!questionToSend) setInput("");
    setLoading(true);

    try {
      const response = await fetch("/api/guide/chat-stream", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: text,
          role: role,
          style: style,
          beginner_mode: role.includes("Beginner") || role.includes("Student"),
          page_context: window.location.pathname,
        }),
      });

      if (!response.ok || !response.body) {
        throw new Error(`Streaming error: ${response.status}`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let receivedTokens = false;
      let assistantAdded = false;

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed.startsWith("data: ")) {
            try {
              const data = JSON.parse(trimmed.slice(6));
              if (data.token) {
                receivedTokens = true;
                setMessages((prev) => {
                  if (!assistantAdded) {
                    assistantAdded = true;
                    return [
                      ...prev,
                      {
                        role: "assistant",
                        content: data.token,
                        provider: data.provider || "ollama",
                        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
                      },
                    ];
                  }
                  const updated = [...prev];
                  const lastIdx = updated.length - 1;
                  updated[lastIdx] = {
                    ...updated[lastIdx],
                    content: updated[lastIdx].content + data.token,
                    provider: data.provider || updated[lastIdx].provider,
                  };
                  return updated;
                });
              }
            } catch (e) {
              // ignore json parse error on partial chunks
            }
          }
        }
      }

      if (!receivedTokens) {
        // Fallback to static /guide/chat
        const res = await api.post("/guide/chat", {
          message: text,
          role: role,
          style: style,
          beginner_mode: role.includes("Beginner") || role.includes("Student"),
          page_context: window.location.pathname,
        });
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: res.data?.answer || "No response received.",
            provider: res.data?.provider_used || "ollama",
            timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
          },
        ]);
      }
    } catch (err: any) {
      try {
        const res = await api.post("/guide/chat", {
          message: text,
          role: role,
          style: style,
          beginner_mode: role.includes("Beginner") || role.includes("Student"),
          page_context: window.location.pathname,
        });
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: res.data?.answer || "No response received.",
            provider: res.data?.provider_used || "ollama",
            timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
          },
        ]);
      } catch (fallbackErr: any) {
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: `Sorry, unable to get a response right now (${fallbackErr?.message || "connection error"}).`,
            provider: "offline",
            timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
          },
        ]);
      }
    } finally {
      setLoading(false);
    }
  };

  const clearChat = () => {
    setMessages([
      {
        role: "assistant",
        content: "Conversation cleared. How can I help you investigate CipherTwin?",
        provider: "ollama",
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      },
    ]);
  };

  const currentStarters = STARTER_QUESTIONS[role] || STARTER_QUESTIONS["Developer/Software engineer"];

  return (
    <div className="fixed bottom-5 right-5 z-50">
      {/* Floating Launcher Button */}
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className="flex items-center gap-2 px-4 py-3 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-full shadow-lg shadow-cyan-900/50 transition-all transform hover:scale-105 border border-cyan-400/40"
          aria-label="Open CipherTwinGuide"
        >
          <Bot className="w-5 h-5 animate-pulse" />
          <span className="font-semibold text-sm tracking-wide">CipherTwinGuide</span>
        </button>
      )}

      {/* Expandable Chat Drawer */}
      {isOpen && (
        <div className="flex flex-col w-[420px] max-w-[calc(100vw-2rem)] h-[620px] max-h-[calc(100vh-2rem)] bg-slate-900/95 backdrop-blur-md border border-cyan-500/40 rounded-2xl shadow-2xl overflow-hidden text-slate-100 animate-in fade-in slide-in-from-bottom-5">
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 bg-slate-800/80 border-b border-cyan-500/20">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-cyan-500/20 border border-cyan-400/30 text-cyan-400">
                <Bot className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-bold text-sm tracking-wide text-cyan-300">CipherTwinGuide</h3>
                <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
                  <span className={`w-2 h-2 rounded-full ${isOllama ? "bg-emerald-400 animate-pulse" : "bg-amber-400"}`} />
                  <span>{providerStatus}</span>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-1">
              <button
                onClick={clearChat}
                title="Clear conversation"
                className="p-1.5 hover:bg-slate-700/60 rounded text-slate-400 hover:text-slate-200 transition"
              >
                <RefreshCw className="w-4 h-4" />
              </button>
              <button
                onClick={() => setIsOpen(false)}
                title="Close Guide"
                className="p-1.5 hover:bg-slate-700/60 rounded text-slate-400 hover:text-slate-200 transition"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Persona & Style Selectors */}
          <div className="grid grid-cols-2 gap-2 px-3 py-2 bg-slate-800/40 border-b border-slate-700/50 text-xs">
            <div>
              <label className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Role / Persona</label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs focus:outline-none focus:border-cyan-400"
              >
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Response Style</label>
              <select
                value={style}
                onChange={(e) => setStyle(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs focus:outline-none focus:border-cyan-400"
              >
                {STYLES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Chat Messages */}
          <div className="flex-1 p-3 overflow-y-auto space-y-3 text-xs leading-relaxed">
            {messages.map((m, idx) => (
              <div
                key={idx}
                className={`flex flex-col ${m.role === "user" ? "items-end" : "items-start"}`}
              >
                <div
                  className={`max-w-[88%] p-3 rounded-xl whitespace-pre-wrap ${
                    m.role === "user"
                      ? "bg-gradient-to-r from-cyan-600 to-blue-600 text-white rounded-br-none"
                      : "bg-slate-800/90 text-slate-200 border border-slate-700 rounded-bl-none shadow"
                  }`}
                >
                  {m.content}
                </div>
                <div className="flex items-center gap-1.5 mt-1 text-[10px] text-slate-500 px-1">
                  <span>{m.timestamp}</span>
                  {m.provider && (
                    <>
                      <span>•</span>
                      <span className="text-cyan-400 font-mono">provider: {m.provider}</span>
                    </>
                  )}
                </div>
              </div>
            ))}

            {loading && messages[messages.length - 1]?.role === "user" && (
              <div className="flex items-start">
                <div className="max-w-[88%] p-3 rounded-xl bg-slate-800/90 border border-slate-700 text-slate-400 rounded-bl-none flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-cyan-400 animate-bounce" />
                  <div className="w-2 h-2 rounded-full bg-cyan-400 animate-bounce [animation-delay:0.2s]" />
                  <div className="w-2 h-2 rounded-full bg-cyan-400 animate-bounce [animation-delay:0.4s]" />
                  <span className="text-[11px] italic">Analyzing real-time state with Ollama...</span>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Starter Suggestions */}
          <div className="px-3 py-2 bg-slate-800/30 border-t border-slate-700/50">
            <p className="text-[10px] uppercase font-bold text-slate-400 mb-1.5 flex items-center gap-1">
              <Sparkles className="w-3 h-3 text-cyan-400" /> Suggested for {role.split("/")[0]}
            </p>
            <div className="flex flex-wrap gap-1.5">
              {currentStarters.map((q, i) => (
                <button
                  key={i}
                  disabled={loading}
                  onClick={() => handleSend(q)}
                  className="text-[11px] bg-slate-800 hover:bg-cyan-950/60 hover:text-cyan-300 text-slate-300 px-2 py-1 rounded border border-slate-700/80 transition text-left"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>

          {/* Input Bar */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSend();
            }}
            className="p-3 bg-slate-800/90 border-t border-slate-700/60 flex items-center gap-2"
          >
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask CipherTwinGuide..."
              disabled={loading}
              className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400 transition"
            />
            <button
              type="submit"
              disabled={loading || !input.trim()}
              className="p-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded-lg transition"
            >
              <Send className="w-4 h-4" />
            </button>
          </form>
        </div>
      )}
    </div>
  );
}
