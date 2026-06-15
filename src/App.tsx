import { useState, useRef } from "react";
import "./App.css";

/**
 * Interface representing the structure of updates received from the
 * backend simulation via WebSocket.
 */
interface SimUpdate {
  /** Current status: starting, running, complete, exhausted, or error. */
  status: string;
  /** Which attack strategy is running: brute_force, dictionary, or mask. */
  method?: string;
  /** Hash algorithm in use: md5, sha1, sha256, or bcrypt. */
  algorithm?: string;
  /** Charset preset used for brute-force runs. */
  charset?: string;
  /** Max candidate length used for brute-force runs. */
  max_length?: number;
  /** Mask string used for mask runs. */
  mask?: string;
  /** The latest candidate trialled by the cracker. */
  current_guess?: string;
  /** Cumulative attempts performed in the current run segment. */
  attempts?: number;
  /** Total number of attempts performed throughout the entire run. */
  total_attempts?: number;
  /** Seconds elapsed since the start of the run. */
  elapsed?: number;
  /** Current cracking throughput in guesses per second. */
  speed?: number;
  /** Mathematical complexity of the search space in bits. */
  entropy?: number;
  /** Total possible candidates in the search space. */
  search_space?: number;
  /** The final discovered password (only on 'complete' status). */
  password?: string;
  /** Total duration of the successful crack. */
  time_taken?: number;
  /** Non-fatal advisory (e.g. bcrypt intractability warning). */
  warning?: string;
  /** Informational message (e.g. "search space exhausted"). */
  message?: string;
  /** Human-readable error message if something went wrong. */
  error?: string;
}

type Algorithm = "md5" | "sha1" | "sha256" | "bcrypt";
type AttackMode = "brute_force" | "dictionary" | "mask";
type Charset = "lower" | "upper" | "digits" | "alphanumeric" | "all";

/**
 * Main application component for the Password Cracker Simulator.
 * Manages WebSocket connections, global simulation state, and dashboard layout.
 */
function App() {
  // Target hash + algorithm selection.
  const [targetHash, setTargetHash] = useState("");
  const [algorithm, setAlgorithm] = useState<Algorithm>("sha256");
  // Attack mode + mode-specific params.
  const [attackMode, setAttackMode] = useState<AttackMode>("brute_force");
  const [charset, setCharset] = useState<Charset>("lower");
  const [maxLength, setMaxLength] = useState<number>(4);
  const [mask, setMask] = useState<string>("?l?l?l?d");

  const [isSimulating, setIsSimulating] = useState(false);
  /** Stores the most recent update from the backend, merging state where appropriate. */
  const [stats, setStats] = useState<SimUpdate | null>(null);
  /** Reference to the active WebSocket connection for cleanup and manual cancellation. */
  const ws = useRef<WebSocket | null>(null);

    /**
     * Initiates the cracking simulation by opening a WebSocket connection to
     * the backend and sending the AttackRequest payload.
     */
    const runSimulation = () => {
    if (!targetHash.trim()) {
      setStats({ status: "error", error: "Target hash is required" });
      return;
    }
    if (attackMode === "mask" && !mask.trim()) {
      setStats({ status: "error", error: "Mask is required when attack_mode=mask" });
      return;
    }

    // Ensure previous connections are closed before starting new one
    if (ws.current) ws.current.close();

    // Reset dashboard state for new run
    setStats(null);
    setIsSimulating(true);

    const BACKEND_URL = import.meta.env.VITE_BACKEND_WS_URL || "ws://localhost:8000";
    const socket = new WebSocket(`${BACKEND_URL}/ws/simulate`);
    ws.current = socket;

    const payload = {
      hash: targetHash.trim(),
      algorithm,
      attack_mode: attackMode,
      charset,
      max_length: maxLength,
      mask: attackMode === "mask" ? mask.trim() : undefined,
    };

    socket.onopen = () => {
      console.log("WebSocket Connection Opened");
      socket.send(JSON.stringify(payload));
    };

    socket.onmessage = (event) => {
      try {
        const data: SimUpdate = JSON.parse(event.data);
        
        // Merge state to ensure fields like entropy from 'starting' message 
        // are preserved during 'running' updates.
        setStats(prev => ({ ...prev, ...data }));
        
        if (data.status === "complete" || data.error) {
          setIsSimulating(false);
          socket.close();
        }
      } catch (err) {
        console.error("Failed to parse message:", err);
      }
    };

    socket.onclose = (event) => {
      console.log("WebSocket Connection Closed", event.code, event.reason);
      setIsSimulating(false);
    };

    socket.onerror = (err) => {
      console.error("WebSocket Connection Error:", err);
      setStats({ status: "error", error: "Connection to backend failed. Ensure 'npm run dev:server' is running." });
      setIsSimulating(false);
    };
  };


  return (
    <div className="min-h-screen bg-bg text-fg flex flex-col items-center justify-center p-4">
      {/* App Name Badge */}
      <div className="fui-app-badge">BRUTE.EXE — A Password Attack Simulator</div>

      {/* Dashboard Grid Layout */}
      <div className="fui-dashboard-grid">
        
        {/* Slot 1: Cipher Strength - Displays bit-level complexity */}
        <div className="fui-grid-cell">
          <div className="fui-label">Cipher Strength</div>
          <CipherStrength value={stats?.entropy || 0} max={128} />
          <div className="text-[10px] opacity-40 mt-8">VEC_ANALYSIS: {isSimulating ? "RUNNING" : "STANDBY"}</div>
        </div>

        {/* Slot 2: Vector Status Indicator - Replaced with Tick Animation */}
        <div className="fui-grid-cell flex-center">
          <div className="fui-label self-start">Vector Status</div>
          <div className="relative-center">
            <AttackTicks active={isSimulating} />
          </div>
          <div className="text-[10px] opacity-20 uppercase">Real-Time Vector Hash Flow</div>
        </div>

        {/* Slot 3: Chrono-Vector - Dual-Ring Timer and Completion Status */}
        <div className="fui-grid-cell flex-center">
          <div className="fui-label self-start">Chrono-Vector / Progress</div>
          <div className="relative-center">
            <TimerRings 
              seconds={stats?.time_taken ?? (stats?.elapsed ? stats.elapsed % 60 : 0)} 
              minutes={stats?.elapsed ? Math.floor(stats.elapsed / 60) : 0}
              active={isSimulating}
            />
            {stats?.status === "complete" && (
              <div className="fui-complete-status">100% COMPLETE</div>
            )}
          </div>
          <div className="text-[10px] opacity-40 uppercase">Duration & Transfer Integrity</div>
        </div>

        {/* Slot 4: Speed - Real-time cracking throughput */}
        <div className="fui-grid-cell min-h-[200px]">
          <div className="fui-label">Cracking Speed</div>
          <div className="fui-value">
            {stats?.speed?.toLocaleString() || "0"} <span className="text-xs opacity-40">G/S</span>
          </div>
          <div className="text-[10px] opacity-40 uppercase">Final Rate</div>
        </div>

        {/* Slot 5: Details - Shows current trial or final password */}
        <div className="fui-grid-cell">
          <div className="fui-label">Transfer Details</div>
          <div className="space-y-6">
            <div>
              <div className="text-[10px] opacity-40 mb-1">FINAL_KEY / CURRENT_GUESS</div>
              <div style={{border:'1px solid var(--fg)', padding:'0.75rem 1rem'}} className="font-bold text-lg tabular-nums truncate max-w-full">
                {stats?.password || stats?.current_guess || "----"}
              </div>
            </div>
            <div>
              <div className="text-[10px] opacity-40 mb-1">TOTAL_CYCLES</div>
              <div style={{border:'1px solid var(--fg)', padding:'0.75rem 1rem'}} className="text-sm">
                {(stats?.total_attempts || stats?.attempts || 0).toLocaleString()}
              </div>
            </div>
          </div>
          <div className="text-[10px] opacity-40 uppercase flex gap-4">
            <span>FROM: LOCAL</span>
            <span>TO: TARGET_VEC</span>
          </div>
        </div>

        {/* Slot 6: Actions - Attack configuration + run/cancel controls */}
        <div className="fui-grid-cell">
          <div className="fui-label">Actions</div>
          <div className="space-y-2">
            {!isSimulating ? (
              <div className="space-y-2 pt-2">
                <input
                  type="text"
                  value={targetHash}
                  onChange={(e) => setTargetHash(e.target.value)}
                  placeholder="Target hash (e.g. SHA-256 digest)"
                  className="fui-input"
                />
                <div className="flex gap-2">
                  <select
                    value={algorithm}
                    onChange={(e) => setAlgorithm(e.target.value as Algorithm)}
                    className="fui-input flex-1"
                  >
                    <option value="md5">MD5</option>
                    <option value="sha1">SHA-1</option>
                    <option value="sha256">SHA-256</option>
                    <option value="bcrypt">bcrypt</option>
                  </select>
                  <select
                    value={attackMode}
                    onChange={(e) => setAttackMode(e.target.value as AttackMode)}
                    className="fui-input flex-1"
                  >
                    <option value="brute_force">Brute force</option>
                    <option value="dictionary">Dictionary</option>
                    <option value="mask">Mask</option>
                  </select>
                </div>
                {attackMode === "brute_force" && (
                  <div className="flex gap-2">
                    <select
                      value={charset}
                      onChange={(e) => setCharset(e.target.value as Charset)}
                      className="fui-input flex-1"
                    >
                      <option value="lower">lower</option>
                      <option value="upper">upper</option>
                      <option value="digits">digits</option>
                      <option value="alphanumeric">alphanumeric</option>
                      <option value="all">all</option>
                    </select>
                    <input
                      type="number"
                      min={1}
                      max={8}
                      value={maxLength}
                      onChange={(e) => setMaxLength(Number(e.target.value))}
                      className="fui-input w-20"
                      title="Max candidate length"
                    />
                  </div>
                )}
                {attackMode === "mask" && (
                  <input
                    type="text"
                    value={mask}
                    onChange={(e) => setMask(e.target.value)}
                    placeholder="Mask (e.g. ?l?l?l?d?d)"
                    className="fui-input"
                  />
                )}
                <button onClick={runSimulation} className="fui-btn fui-btn-primary">Initiate Attack</button>
              </div>
            ) : (
              <div className="space-y-2">
                <button onClick={() => ws.current?.close()} className="fui-btn w-full">Cancel Attack</button>
                <div className="text-center text-[10px] animate-pulse opacity-50 tracking-widest mt-4">
                  {(stats?.method ?? "ATTACK").toUpperCase()}_ACTIVE
                </div>
              </div>
            )}
            <button className="fui-btn w-full" disabled>Close Window</button>
          </div>
        </div>

      </div>

      {/* Educational Disclaimer */}
      <div className="fui-disclaimer">
        <span className="fui-disclaimer-badge"><span className="fui-disclaimer-badge-icon">⚠</span> EDUCATIONAL USE ONLY</span>
        <p>
          This Python Password Cracker Simulator is an educational cybersecurity application that safely imitates password 
          attack techniques against user-provided sample passwords in order to demonstrate password vulnerability, estimate 
          password strength, visualize attack behavior, and provide practical security recommendations.
        </p>
      </div>

      {/* Full-Screen Completion Modal */}
      {stats?.status === "complete" && (
        <div className="fui-modal-overlay">
          <div className="fui-modal-content animate-in">
            <div className="fui-modal-title">Result Confirmed</div>
            <div className="text-6xl font-bold tracking-tighter mb-4">KEYFOUND</div>
            
            {/* Final Performance Metrics */}
            <div className="flex gap-4 mb-8">
              <div className="border border-border p-4 text-center min-w-[120px]">
                <div className="text-[8px] opacity-40 mb-1 uppercase tracking-widest">Time Taken</div>
                <div className="text-xl font-bold">{stats.time_taken?.toFixed(4)}s</div>
              </div>
              <div className="border border-border p-4 text-center min-w-[120px]">
                <div className="text-[8px] opacity-40 mb-1 uppercase tracking-widest">Total Cycles</div>
                <div className="text-xl font-bold">{stats.total_attempts?.toLocaleString()}</div>
              </div>
            </div>

            {/* Discovered Password Block */}
            <div className="border-4 border-border p-12 text-center bg-white/5 backdrop-blur-sm w-full">
              <div className="text-[10px] opacity-40 mb-4 tracking-[0.5em] uppercase">Extracted Password</div>
              <div className="text-4xl font-bold bg-[#d1e0c2] text-[#171c1c] px-8 py-4 tabular-nums">{stats.password}</div>
            </div>
            <button onClick={() => setStats(prev => prev ? { ...prev, status: "idle" } : null)} className="fui-btn mt-12 max-w-[200px]">Resume Host</button>
          </div>
        </div>
      )}

      {/* Global Error Banner */}
      {stats?.error && (
        <div className="fixed bottom-8 right-8 border border-red-900 bg-red-950/20 p-4 text-red-500 text-[10px] uppercase tracking-widest">
          ERROR: {stats.error}
        </div>
      )}
    </div>
  );
}

/**
 * Component displaying a multi-segmented complexity indicator for the target password.
 */
function CipherStrength({ value, max }: { value: number; max: number }) {
  const percent = Math.min(100, (value / max) * 100);
  const barCount = 24;
  const activeBars = Math.floor((percent / 100) * barCount);

  return (
    <div className="mt-4">
      <div className="fui-tag-container">
        <