import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";

export function usePolling<T>(
  url: string,
  intervalMs = 5000,
): { data: T | null; loading: boolean; refetch: () => Promise<void> } {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const inFlightRef = useRef(false);

  const refetch = useCallback(async () => {
    if (inFlightRef.current) return;
    inFlightRef.current = true;
    try {
      const res = await api.get<T>(url);
      setData(res.data);
      setLoading(false);
    } catch {
      setLoading(false);
    } finally {
      inFlightRef.current = false;
    }
  }, [url]);

  useEffect(() => {
    let active = true;
    refetch();
    const id = setInterval(() => {
      if (active) refetch();
    }, intervalMs);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, [refetch, intervalMs]);

  return { data, loading, refetch };
}
