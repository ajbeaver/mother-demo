function showView(id) {
    document.querySelectorAll(".view").forEach(v => v.classList.add("hidden"));
    const target = document.getElementById("view-" + id);
    if (target) target.classList.remove("hidden");
}

async function fetchJSON(path, options = {}) {
    const res = await fetch(path, options);
    return res.json();
}

/* --------------------------------------------------------
   TYPEWRITER SPLASH LOGIC
---------------------------------------------------------*/

async function runSplash() {
    const pre = document.getElementById("splash-output");
    const enter = document.getElementById("splash-enter");

    const lines = [
        "Initializing Mother Core v1.0...\n",
        "Network perimeter scan in progress...\n",
        "Intrusion detection system online...\n",
        "Threat analysis protocols active...\n",
        "Sentinel core activated — all vulnerable sectors are being monitored...\n",
        "",
        "-----",
        "Press ENTER to continue to Mother Dashboard..."
    ];

    pre.textContent = "";
    enter.classList.add("hidden");

    const lineEls = lines.map(() => {
        const el = document.createElement("div");
        el.className = "splash-line";
        el.textContent = "";
        pre.appendChild(el);
        return el;
    });

    let lineIndex = 0;
    let charIndex = 0;

    function typeNext() {
        const line = lines[lineIndex];
        const el = lineEls[lineIndex];

        el.textContent += line[charIndex];
        charIndex++;

        if (charIndex < line.length) {
            setTimeout(typeNext, 28);
            return;
        }

        lineIndex++;
        charIndex = 0;

        if (lineIndex < lines.length - 1) {
            setTimeout(typeNext, 500);
            return;
        }

        if (lineIndex === lines.length - 1) {
            setTimeout(typeNext, 120);
            return;
        }

        enter.classList.remove("hidden");
    }

    return new Promise(resolve => {
        typeNext();

        enter.onclick = () => resolve();
        document.addEventListener("keydown", e => {
            if (e.key === "Enter") resolve();
        });
    });
}

/* --------------------------------------------------------
   CHAIN FILTER STATE
---------------------------------------------------------*/

let activeChainFilter = null;

function applyChainFilter(events) {
    if (!activeChainFilter) return events;
    return events.filter(e => e.chain_id === activeChainFilter);
}

/* --------------------------------------------------------
   VIEW LOADERS
---------------------------------------------------------*/

async function updateDashboard() {
    const data = await fetchJSON("/api/dashboard");

    document.getElementById("count-benign").textContent = data.counts.benign;
    document.getElementById("count-suspicious").textContent = data.counts.suspicious;
    document.getElementById("count-malicious").textContent = data.counts.malicious;
    document.getElementById("count-critical").textContent = data.counts.critical;

    document.getElementById("posture-value").textContent = data.posture;
}

async function loadEvents() {
    // Guard: ensure Events DOM exists before running
    const container = document.getElementById("events-container");
    const banner = document.getElementById("chain-filter-banner");
    const clearBtn = document.getElementById("clear-chain-btn");

    if (!container || !banner || !clearBtn) {
        return; // prevents fatal crash
    }

    const data = await fetchJSON("/api/events");
    const filtered = applyChainFilter(data);

    container.innerHTML = "";

    if (activeChainFilter) {
        banner.style.display = "block";
        banner.textContent = "Filtering by chain: " + activeChainFilter;
        clearBtn.style.display = "inline-block";
    } else {
        banner.style.display = "none";
        clearBtn.style.display = "none";
    }

    filtered.forEach(evt => {
        const div = document.createElement("div");
        div.className = "event-row";

        const ts = evt.timestamp?.split("T")[1]?.split(".")[0] || "";

        div.textContent =
            `[${ts}] [${evt.severity}] ${evt.source_ip} → ${evt.dest_port}` +
            (evt.chain_id ? `  (chain ${evt.chain_id})` : "");

        div.onclick = () => {
            window.location = "/inspector?id=" + evt.id;
        };

        container.appendChild(div);
    });
}

async function loadInspector() {
    const params = new URLSearchParams(window.location.search);
    const id = params.get("id");
    if (!id) return;

    const data = await fetchJSON("/api/events/" + id);

    document.getElementById("inspector-output").textContent =
        JSON.stringify(data, null, 2);

    const chainBtn = document.getElementById("inspect-chain-btn");

    if (data.chain_id) {
        chainBtn.classList.remove("hidden");
        chainBtn.onclick = () => {
            activeChainFilter = data.chain_id;
            window.location = "/events?chain=" + data.chain_id;
        };
    } else {
        chainBtn.classList.add("hidden");
    }
}

/* --------------------------------------------------------
   BUTTONS
---------------------------------------------------------*/

async function bindButtons() {
    const btn = document.getElementById("attack-btn");
    if (btn) {
        btn.onclick = async () => {
            await fetchJSON("/api/attack/trigger", { method: "POST" });
            await updateDashboard();
            await loadEvents();
        };
    }

    const clearBtn = document.getElementById("clear-chain-btn");
    if (clearBtn) {
        clearBtn.onclick = () => {
            activeChainFilter = null;
            loadEvents();
        };
    }
}

/* --------------------------------------------------------
   POLLING
---------------------------------------------------------*/

async function startPolling() {
    setInterval(() => {
        const path = window.location.pathname;
        if (path === "/dashboard") updateDashboard();
        if (path === "/events") loadEvents();
        if (path.startsWith("/inspector")) loadInspector();
    }, 1500);
}

/* --------------------------------------------------------
   ROUTING + INIT
---------------------------------------------------------*/

function route() {
    const path = window.location.pathname;

    if (path === "/dashboard") showView("dashboard");
    else if (path === "/events") showView("events");
    else if (path === "/console") showView("console");
    else if (path.startsWith("/inspector")) showView("inspector");
    else showView("splash");
}

async function init() {
    const params = new URLSearchParams(window.location.search);
    const chain = params.get("chain");
    if (chain) activeChainFilter = chain;

    if (window.location.pathname === "/") {
        showView("splash");
        await runSplash();
        showView("dashboard");
        history.pushState({}, "", "/dashboard");
    }

    route();
    bindButtons();
    startPolling();
}

init();
