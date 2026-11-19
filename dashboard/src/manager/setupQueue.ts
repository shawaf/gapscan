import { useEffect, useState } from "preact/hooks";
import { api, ApiError } from "./api";
import type { Task } from "./api";
import { useLoad } from "./useApi";

export interface Item { step: string; pack?: string; label: string }

/** Runs setup steps one after another on the server (downloads, installs, starting the engine) and reports progress.
 *  `after` is called whenever a step ends, so the page can reload what is installed. */
export function useSetupQueue(after: () => void, adopt?: string | null) {
  const [queue, setQueue] = useState<Item[]>([]);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [label, setLabel] = useState("");
  const [current, setCurrent] = useState("");
  const [msg, setMsg] = useState("");
  const [finished, setFinished] = useState<"idle" | "done" | "failed">("idle");
  const task = useLoad<Task | null>(() => (taskId ? api<Task>("GET", `/api/tasks/${taskId}`) : Promise.resolve(null)), [taskId], (t) => t?.status === "running", 700);

  const launch = async (item: Item) => {
    try {
      const r = await api<{ id: string }>("POST", "/api/setup/run", { step: item.step, pack: item.pack ?? "" });
      setTaskId(r.id); setLabel(item.label); setCurrent(item.step); setMsg("");
    } catch (x) { setMsg(x instanceof ApiError ? x.message : String(x)); setQueue([]); setFinished("failed"); }
  };
  const begin = (items: Item[]) => {
    const [first, ...rest] = items;
    setFinished("idle");
    if (first) { setQueue(rest); void launch(first); } else setFinished("done");
  };

  // a step that was already running (the page was opened again) is picked up
  useEffect(() => { if (!taskId && adopt) { setTaskId(adopt); setLabel("Working"); } }, [adopt]);
  useEffect(() => {
    const t = task.data;
    if (!t || t.status === "running" || t.id !== taskId) return;
    after();
    if (t.status === "done" && queue.length) { const [next, ...rest] = queue; setQueue(rest); void launch(next as Item); }
    else if (t.status === "done") setFinished("done");
    else { setQueue([]); setFinished("failed"); }
  }, [task.data?.id, task.data?.status, taskId]);

  const running = task.data?.status === "running" || queue.length > 0;
  const cancel = async () => {
    if (taskId) { try { await api("POST", `/api/tasks/${taskId}/cancel`, {}); } catch { /* already finished */ } }
    setQueue([]);
  };
  return { begin, running, task: task.data, label, current, waiting: queue.map((i) => i.step), msg, cancel, finished };
}
