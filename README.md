# Mother Demo  
A Real-Time Autonomous Security Simulator for the Web

Mother Demo is a fully self-contained web application that simulates real-world network telemetry, attacker chains, system posture, and intelligent defensive recommendations. It is designed to feel like an operator’s console: events stream in live, attack chains unfold over time with coherent narrative structure, and the system evaluates posture in real time based on its own classification and policy engine.

This project demonstrates how a modern web stack can model autonomous behavior without external AI services, using deterministic logic, clean architecture, and a responsive UI.

---

## Concept

Most security demos rely on static logs or canned animations. Mother Demo instead generates *living telemetry*. Noise events, recon scans, intrusion attempts, and exploit stages are synthesized using real templates with realistic metadata. These events roll through a backend pipeline where they are classified, grouped into chains, evaluated for risk, and used to derive a dynamic system posture.

At the frontend, users can watch events appear in real time, filter by chain, drill into details, and trigger full simulated attack sequences. This creates an environment that looks and behaves like an active system undergoing real activity.

The focus is not on machine learning, but on *explainable logic*: every classification, every risk escalation, and every recommended action is derived from transparent, rule-based modules.

---

## Tech Stack

**Frontend**  
• Vanilla JavaScript (no frameworks)  
• Live event polling  
• In-browser chain filtering & inspector view  
• Terminal-style splash + dashboard UI  

**Backend**  
• FastAPI (Python)  
• Event generator (noise + templated attacks)  
• Attack engine producing coherent multi-stage chains  
• Classification engine (event + chain risk scoring)  
• Posture engine (MONITOR → ELEVATED → RESTRICT → LOCKDOWN)  
• Recommendation engine (per-event, per-chain, and global posture guidance)

**Infrastructure**  
• Stateless server runtime  
• Pure Python environment with no external APIs  
• SSH-deployable and container-friendly layout

---

## How It Works

1. **Noise Loop**  
   Generates benign operational telemetry every 0.5–0.8 seconds.

2. **Attack Engine**  
   Builds multi-stage chains (recon → intrusion → exploit) with unique chain IDs, realistic metadata, and timed release delays across 20–40 seconds.

3. **Scheduler**  
   Emits each event at real execution time. Timestamps reflect *when* something happened, not when simulation started.

4. **Classifier**  
   Scores each event and chain for risk, confidence, and contributing factors.

5. **Posture Engine**  
   Evaluates the last N seconds of activity to choose the correct defensive posture.

6. **Recommendations**  
   Produces human-readable suggested actions: investigate, block, isolate, restrict, enhance logging, etc.

7. **Frontend**  
   Pulls events and posture live, displaying them as a stream with chain awareness and an interactive inspector.

---

## Why It Matters

Mother Demo shows how a modern web application can simulate autonomy, causality, and live system behavior without opaque ML models. Everything is inspectable, traceable, and understandable. For education, training, demonstrations, and rapid prototyping of security concepts, this structure is ideal.

The focus is not “AI magic,” but building *systems that behave intelligently* through clear design.

---

## Live Demo  
(Insert deployment URL)

## Repository  
https://github.com/ajbeaver/mother-demo

---

## Team  
Solo project by A.J. Beaver

---

## License  
MIT
