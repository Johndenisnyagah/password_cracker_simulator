import { useState, useRef } from "react";
import "./App.css";

/**
 * Interface representing the structure of updates received from the 
 * backend simulation via WebSocket.
 */
interface SimUpdate {
  /** Current status of the simulation: starting, running, complete, or error. */
  status: string;
  /** The latest character string trial attempted by the simulator. */
  current_guess?: string;
  /** Cumulative attempts performed in the current simulation segment. */
  attempts?: number;
  /** Total number of attempts performed throughout the entire simulation. */
  total_attempts?: number;
  /** Seconds elapsed since the start of the simulation. */
  elapsed?: number;
  /** Current cracking throughput in guesses per second. */
  speed?: number;
  /** Mathematical complexity of the target password in bits. */
  entropy?: number;
  /** Total possible combinations in the character search space. */
  search_space?: number;
  /** The final discovered password (only on 'complete' status). */
  password?: string;
  /** Total duration of the successful crack. */
  time_taken?: number;
  /** Human-readable error message if something went wrong. */
  error?: string;
}

/**
 * Main application component for the Password Cracker Simulator.
 * Manages WebSocket connections, global simulation state, and dashboard layout.
 */
function App() {
  const [targetPassword, setTargetPassword] = useState("");
  const [isSimulating, setIsSimulating] = useState(false);
  /** Stores the most recent update from the backend, merging state where appropriate. */
  const [stats, setStats] = useState<SimUpdate | null>(null);
  /** Reference to the active WebSocket connection for cleanup and manual cancellation. */
  const ws = useRef<WebSocket | null>(null);

    /**
     * Initiates the password cracking simulation by opening a WebSocket
     * connection to the backend and sending the target password.
     */
    const runSimulation = () => {
    if (!targetPassword) return;
    
    // Client-side length validation (mirrors backend protection)
    if (targetPassword.length > 64) {
      setStats({ status: "error", error: "Password too long (max 64 chars)" });
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
    
    socket.onopen = () => {
      console.log("WebSocket Connection Opened");
      socket.send(JSON.stringify({ password: targetPassword }));
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

        {/* Slot 6: Actions - Unified control for simulation and input */}
        <div className="fui-grid-cell">
          <div className="fui-label">Actions</div>
          <div className="space-y-2">
            {!isSimulating ? (
              <div className="space-y-2 pt-2">
                <input 
                  type="text" 
                  value={targetPassword}
                  onChange={(e) => setTargetPassword(e.target.value)}
                  placeholder="Enter target password"
                  className="fui-input"
                />
                <button onClick={runSimulation} className="fui-btn fui-btn-primary">Initiate Attack</button>
              </div>
            ) : (
              <div className="space-y-2">
                <button onClick={() => ws.current?.close()} className="fui-btn w-full">Cancel Attack</button>
                <div className="text-center text-[10px] animate-pulse opacity-50 tracking-widest mt-4">BRUTE_FORCE_ACTIVE</div>
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
        <span className="fui-tag">dev</span>
        <span className="fui-tag">back-end</span>
        <span className="fui-tag">architecture</span>
      </div>
      <h2 className="fui-strength-title">Extended</h2>
      <p className="fui-strength-subtitle">Entropy analysis for target security vector.</p>
      
      <div className="fui-strength-stats">
        <span className="fui-strength-percent">{Math.round(percent)}%</span>
        <div className="fui-strength-trend">
          <div className="fui-trend-box">↗ {value.toFixed(1)}</div>
          <span className="opacity-40">since standby</span>
        </div>
      </div>

      <div className="fui-strength-bars">
        {Array.from({ length: barCount }).map((_, i) => (
          <div 
            key={i} 
            className={`fui-bar ${i < activeBars ? 'fui-bar-active' : ''}`}
          />
        ))}
      </div>
    </div>
  );
}

/**
 * Component for Slot 3: Dual-Ring Timer.
 * Features an inner ring for seconds and an outer ring for minutes using tick marks.
 */
function TimerRings({ seconds, minutes, active }: { seconds: number; minutes: number; active: boolean }) {
  const formatNum = (n: number) => Math.floor(n).toString().padStart(2, '0');
  
  // Create ticks for rings
  const renderTicks = (count: number, radius: number, length: number, current: number, className: string) => {
    return Array.from({ length: count }).map((_, i) => {
      const angle = (i / count) * 360;
      const isActive = i <= (current % count);
      return (
        <line
          key={i}
          x1="90"
          y1={90 - radius}
          x2="90"
          y2={90 - radius + length}
          className={`${className} ${isActive ? 'fui-tick-active' : ''} ${!active && isActive ? 'fui-tick-dim' : ''}`}
          transform={`rotate(${angle}, 90, 90)`}
        />
      );
    });
  };

  return (
    <div className="fui-rings-container">
      <svg width="180" height="180" viewBox="0 0 180 180" className="absolute">
        {/* Outer Ring - Minutes */}
        <g className="fui-outer-ring">
          {renderTicks(60, 80, 8, minutes, "fui-tick")}
        </g>
        {/* Inner Ring - Seconds */}
        <g className="fui-inner-ring">
          {renderTicks(60, 60, 15, seconds, "fui-tick")}
        </g>
      </svg>
      <div className="fui-timer-text tabular-nums">
        {formatNum(minutes)}:{formatNum(seconds)}
      </div>
    </div>
  );
}

/**
 * Component for Slot 2: Vector Hash Flow (GIF-like tick animation).
 * Displays a single ring of dense ticks with a chasing highlight.
 */
function AttackTicks({ active }: { active: boolean }) {
  const [offset, setOffset] = useState(0);

  // Simple animation for the chasing effect
  if (active) {
    setTimeout(() => setOffset((prev) => (prev + 1) % 40), 50);
  }

  return (
    <div className="fui-attack-indicator flex items-center justify-center">
      <svg width="160" height="160" className="overflow-visible">
        {Array.from({ length: 40 }).map((_, i) => {
          const angle = (i / 40) * 360;
          const isActive = active && (i === offset || i === (offset + 1) % 40 || i === (offset + 2) % 40);
          return (
            <line
              key={i}
              x1="80"
              y1="10"
              x2="80"
              y2="25"
              className={`fui-attack-tick ${isActive ? 'fui-attack-tick-active' : ''}`}
              transform={`rotate(${angle}, 80, 80)`}
            />
          );
        })}
      </svg>
      <div className="absolute text-[8px] opacity-50 tracking-tighter text-center max-w-[60px]">
        {active ? "HASH_SYNC_IN_PROGRESS" : "SYSTEM_READY"}
      </div>
    </div>
  );
}

export default App;
