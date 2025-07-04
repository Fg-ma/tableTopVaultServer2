class ServerRequests {
  constructor() {}

  loadRequests = async () => {
    try {
      const res = await fetch("/requests");
      if (!res.ok) throw new Error("Failed to fetch");
      const data = await res.json();

      const list = document.getElementById("requestsList");

      if (!list) return;

      list.innerHTML = "";

      for (const requestId in data) {
        const req = data[requestId];
        const li = document.createElement("li");
        li.className = "request-card";

        const idEl = document.createElement("div");
        idEl.className = "request-id";
        idEl.textContent = requestId;

        const bodyEl = document.createElement("pre");
        bodyEl.className = "request-body";
        bodyEl.textContent = JSON.stringify(req, null, 2);

        const btnRow = document.createElement("div");
        btnRow.style.display = "flex";
        btnRow.style.justifyContent = "flex-end";
        btnRow.style.gap = "0.5rem";

        const acceptBtn = document.createElement("button");
        acceptBtn.className = "accept-btn";
        acceptBtn.textContent = "Accept";
        acceptBtn.addEventListener("click", () => this.sendAccept(requestId));

        const declineBtn = document.createElement("button");
        declineBtn.className = "accept-btn";
        declineBtn.style.backgroundColor = "var(--tone-black-6)";
        declineBtn.textContent = "Decline";
        declineBtn.addEventListener("click", () => this.sendDecline(requestId));

        btnRow.append(acceptBtn, declineBtn);

        li.append(idEl, bodyEl, btnRow);
        list.appendChild(li);
      }
    } catch (e) {
      console.error(e);
    }
  };

  sendAccept = async (requestId: string) => {
    try {
      const res = await fetch("/accept", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ request_id: requestId }),
      });
      if (res.ok) this.loadRequests();
      else console.error("Approve failed");
    } catch (e) {
      console.error(e);
    }
  };

  sendDecline = async (requestId: string) => {
    try {
      const res = await fetch("/decline", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ request_id: requestId }),
      });
      if (res.ok) this.loadRequests();
      else console.error("Decline failed");
    } catch (e) {
      console.error(e);
    }
  };
}

const serverRequests = new ServerRequests();

document.getElementById("loginForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();

  const vaultTokenInput = document.getElementById(
    "vaultToken"
  ) as HTMLInputElement;

  if (!vaultTokenInput) return;

  const token = vaultTokenInput.value;
  const res = await fetch("/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
  });
  if (res.ok) {
    const loginOverlay = document.getElementById("loginOverlay");
    if (loginOverlay) loginOverlay.style.display = "none";
    serverRequests.loadRequests();
  } else {
    const loginError = document.getElementById("loginError");
    if (loginError) loginError.textContent = "Invalid token";
  }
});

window.addEventListener("load", serverRequests.loadRequests);
setInterval(serverRequests.loadRequests, 5000);
