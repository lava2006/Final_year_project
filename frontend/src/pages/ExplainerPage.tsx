import { Activity, AlertTriangle, Bot, Eye, Lightbulb, ShieldCheck, Skull, Sparkles } from "lucide-react";
import { usePolling } from "@/hooks/usePolling";
import type { RiskDecision, BehaviourAnalysis } from "@/lib/types";
import { SectionHeader } from "@/components/SectionHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { RiskBadge } from "@/components/RiskBadge";
import { formatDateTime, riskColor } from "@/lib/utils";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

export default function ExplainerPage() {
  const decisions = usePolling<{ items: RiskDecision[]; total: number }>(
    "/risk/decisions?page=1&page_size=20",
    5000,
  );
  const improvements = usePolling<any[]>("/optimization/history?limit=10", 10000);
  const behaviour = usePolling<BehaviourAnalysis>("/risk/behaviour-analysis", 5000);

  const items = decisions.data?.items ?? [];
  const bData = behaviour.data;

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Explainability Engine"
        description="Every Zero Trust decision and every optimization is paired with a human-readable narrative."
      />

      {/* Behaviour Analysis Percentages Card */}
      <Card className="border-cyber-cyan/30 bg-card/60">
        <CardHeader className="pb-2">
          <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
            <CardTitle className="flex items-center gap-2 text-base">
              <Activity className="h-4 w-4 text-cyber-cyan" />
              Explainable AI Behavioral Distribution
            </CardTitle>
            <div className="flex items-center gap-3 text-xs text-muted-foreground">
              <span>Total Evaluated: <strong className="text-foreground">{bData?.total_evaluated ?? 0}</strong></span>
              <span>|</span>
              <span>Avg Risk: <strong className="text-foreground">{bData?.average_risk_score ?? 0}</strong></span>
              <span>|</span>
              <span>Confidence: <strong className="text-foreground">{bData?.average_confidence ?? 0}%</strong></span>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4 pt-2">
          <p className="text-xs text-muted-foreground">
            Zero Trust inference continuously analyzes user and entity behavior against baseline digital twin telemetry, dynamically categorizing risk posture into four distinct behavioral classifications.
          </p>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {/* Normal Behaviour */}
            <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3">
              <div className="flex items-center justify-between text-xs">
                <span className="flex items-center gap-1 font-medium text-emerald-400">
                  <ShieldCheck className="h-3.5 w-3.5" /> Normal
                </span>
                <span className="font-mono text-xs text-muted-foreground">
                  {bData?.counts.normal ?? 0} events
                </span>
              </div>
              <div className="mt-2 text-2xl font-bold text-emerald-400">
                {bData?.normal_pct?.toFixed(1) ?? "0.0"}%
              </div>
              <Progress value={bData?.normal_pct ?? 0} className="mt-2 h-1.5 bg-emerald-950" />
              <div className="mt-1.5 text-[11px] text-muted-foreground">
                Authorized access within baseline variance
              </div>
            </div>

            {/* Suspicious Behaviour */}
            <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3">
              <div className="flex items-center justify-between text-xs">
                <span className="flex items-center gap-1 font-medium text-amber-400">
                  <AlertTriangle className="h-3.5 w-3.5" /> Suspicious
                </span>
                <span className="font-mono text-xs text-muted-foreground">
                  {bData?.counts.suspicious ?? 0} events
                </span>
              </div>
              <div className="mt-2 text-2xl font-bold text-amber-400">
                {bData?.suspicious_pct?.toFixed(1) ?? "0.0"}%
              </div>
              <Progress value={bData?.suspicious_pct ?? 0} className="mt-2 h-1.5 bg-amber-950" />
              <div className="mt-1.5 text-[11px] text-muted-foreground">
                Anomalous context requiring step-up verification
              </div>
            </div>

            {/* Anomalous Behaviour */}
            <div className="rounded-lg border border-violet-500/20 bg-violet-500/5 p-3">
              <div className="flex items-center justify-between text-xs">
                <span className="flex items-center gap-1 font-medium text-violet-400">
                  <Eye className="h-3.5 w-3.5" /> Anomalous
                </span>
                <span className="font-mono text-xs text-muted-foreground">
                  {bData?.counts.anomalous ?? 0} events
                </span>
              </div>
              <div className="mt-2 text-2xl font-bold text-violet-400">
                {bData?.anomalous_pct?.toFixed(1) ?? "0.0"}%
              </div>
              <Progress value={bData?.anomalous_pct ?? 0} className="mt-2 h-1.5 bg-violet-950" />
              <div className="mt-1.5 text-[11px] text-muted-foreground">
                Divergent signals rerouted to adaptive decoys
              </div>
            </div>

            {/* Malicious Behaviour */}
            <div className="rounded-lg border border-rose-500/20 bg-rose-500/5 p-3">
              <div className="flex items-center justify-between text-xs">
                <span className="flex items-center gap-1 font-medium text-rose-400">
                  <Skull className="h-3.5 w-3.5" /> Malicious
                </span>
                <span className="font-mono text-xs text-muted-foreground">
                  {bData?.counts.malicious ?? 0} events
                </span>
              </div>
              <div className="mt-2 text-2xl font-bold text-rose-400">
                {bData?.malicious_pct !== undefined ? (bData.malicious_pct > 0 && bData.malicious_pct < 0.1 ? bData.malicious_pct.toFixed(2) : bData.malicious_pct.toFixed(1)) : "0.0"}%
              </div>
              <Progress value={bData?.malicious_pct ?? 0} className="mt-2 h-1.5 bg-rose-950" />
              <div className="mt-1.5 text-[11px] text-muted-foreground">
                High-confidence threat signatures explicitly blocked
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2"><Bot className="h-4 w-4 text-cyber-cyan" />Recent Decision Reasons</CardTitle>
         </CardHeader>
          <CardContent className="space-y-3">
            {decisions.loading && !items.length ? (
              Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24 w-full" />)
            ) : (
              items.slice(0, 6).map((d) => (
                <div key={d.id} className="rounded-lg border border-border bg-card/40 p-3">
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <span className="font-mono">{formatDateTime(d.timestamp)}</span>
                    <RiskBadge decision={d.decision} />
                    <span className="ml-auto">{`user ${d.user_id}`}</span>
                 </div>
                  <div className="mt-1 flex items-center gap-2">
                    <div className="text-2xl font-bold" style={{ color: riskColor(d.risk_score) }}>
                      {d.risk_score.toFixed(0)}
                   </div>
                    <div className="text-xs text-muted-foreground">confidence {d.confidence.toFixed(0)}%</div>
                 </div>
                  <Progress value={d.risk_score} className="mt-1" />
                  <p className="mt-2 text-sm">{`${d.summary}`}</p>
                  <div className="mt-2 grid grid-cols-2 gap-2 text-xs md:grid-cols-3">
                    {d.factors.map((f) => {
                      const isUnobserved = f.score === null || f.score === undefined || (f.score === 0 && f.contribution === 0 && d.risk_score > 0 && f.description?.toLowerCase().includes("unavailable"));
                      return (
                        <TooltipProvider key={f.name}>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <div className="rounded bg-muted/30 p-2 cursor-help transition-colors hover:bg-muted/50">
                                <div className="text-muted-foreground">{`${f.name}`}</div>
                                <div className="font-mono">
                                  {isUnobserved ? (
                                    <span className="text-muted-foreground/70 font-semibold">N/A <span className="text-[10px] text-muted-foreground/50">({f.contribution.toFixed(1)})</span></span>
                                  ) : (
                                    <span>{f.score!.toFixed(0)} <span className="text-[10px] text-muted-foreground">({f.contribution.toFixed(1)})</span></span>
                                  )}
                                </div>
                              </div>
                            </TooltipTrigger>
                            <TooltipContent>
                              <p className="max-w-xs text-xs">{f.description || (isUnobserved ? "Factor context not observed for this principal" : `Score: ${f.score?.toFixed(0)}, weight: ${(f.weight * 100).toFixed(0)}%`)}</p>
                            </TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      );
                    })}
                 </div>
               </div>
              ))
            )}
         </CardContent>
       </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2"><Sparkles className="h-4 w-4 text-cyber-cyan" />Optimization Narratives</CardTitle>
         </CardHeader>
          <CardContent className="space-y-3">
            {(improvements.data ?? []).map((h) => (
              <div key={h.id} className="rounded-lg border border-border bg-card/40 p-3">
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <span className="font-mono">{formatDateTime(h.timestamp)}</span>
                  <Badge variant="info">{`${h.algorithm}`}</Badge>
               </div>
                <div className="mt-2 flex items-center gap-2">
                  <Lightbulb className="h-4 w-4 text-amber-300" />
                  <span className="text-sm">{`${h.summary}`}</span>
               </div>
                <div className="mt-2 flex items-center gap-3 text-xs">
                  <span className="font-mono text-muted-foreground line-through">{h.before_score?.toFixed(2)}</span>
                  <span className="font-mono text-emerald-300">{h.after_score?.toFixed(2)}</span>
                  <span className="ml-auto text-muted-foreground">{h.iterations} iter | {h.duration_ms} ms</span>
               </div>
                <div className="mt-2 space-y-1">
                  {(h.changes ?? []).slice(0, 3).map((c: any, i: number) => (
                    <div key={i} className="flex items-center gap-1 text-xs">
                      <span className="h-2 w-2 rounded-full bg-cyber-cyan inline-block" />
                      <span className="text-muted-foreground">{`${c.policy}`}</span>
                      <span className="font-mono">{c.weight_before.toFixed(2)} to {c.weight_after.toFixed(2)}</span>
                   </div>
                  ))}
               </div>
             </div>
            ))}
            {(!improvements.data || improvements.data.length === 0) && (
              <p className="text-sm text-muted-foreground">No optimization narratives yet</p>
            )}
         </CardContent>
       </Card>
     </div>
   </div>
  );
}
