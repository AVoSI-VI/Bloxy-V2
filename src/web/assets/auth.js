"use strict";

function showLogin() {
  stopPolling();
  $("login").classList.remove("hidden");
  $("login-form").classList.remove("hidden");
  $("login-locked").classList.add("hidden");
  $("auth-warning").classList.add("hidden");
}

async function checkAuth() {
  const response = await fetch("/api/auth/state");
  if (!response.ok) throw new Error("could not read auth state");
  const state = await response.json();

  const needsLogin = state.auth_required && !state.authenticated;
  $("login").classList.toggle("hidden", !needsLogin);
  $("auth-warning").classList.toggle("hidden", state.auth_required);
  $("login-form").classList.toggle("hidden", needsLogin && !state.password_set);
  $("login-locked").classList.toggle("hidden", !needsLogin || state.password_set);
  showTlsHint(state);
  return state;
}

function showTlsHint(state) {
  const hint = $("tls-hint");
  if (!state.tls) {
    hint.textContent = "Takes effect after a restart. The browser must trust the bloxy CA.";
    return;
  }
  const url = `https://${location.host}`;
  hint.textContent =
    location.protocol === "https:"
      ? `Served at ${url}. The browser must trust the bloxy CA. A change takes effect after a restart.`
      : `Restart bloxy, then open ${url}. The browser must trust the bloxy CA.`;
}

function wireAuth() {
  $("login-form").addEventListener("submit", submitLogin);
  $("sign-out").addEventListener("click", signOut);
  $("change-password").addEventListener("submit", changePassword);
  $("generate-token").addEventListener("click", generateToken);
  $("revoke-token").addEventListener("click", revokeToken);
  $("copy-token").addEventListener("click", copyToken);
}

async function submitLogin(event) {
  event.preventDefault();
  const button = event.submitter || $("login-submit");
  button.disabled = true;
  $("login-error").textContent = "";
  try {
    await api("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: $("login-password").value }),
    });
    $("login-password").value = "";
    await loadInterface();
  } catch (error) {
    $("login-error").textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

async function signOut() {
  try {
    await api("/api/auth/logout", { method: "POST" });
  } catch (error) {
    setSaveState(`Sign out failed: ${error.message}`, "failed");
    return;
  }
  $("login-password").value = "";
  $("login-error").textContent = "";
  showLogin();
}

async function changePassword(event) {
  event.preventDefault();
  const message = $("password-message");
  const next = $("password-new").value;
  const confirm = $("password-confirm").value;
  if (next !== confirm) {
    message.textContent = "New passwords do not match.";
    message.className = "error-text";
    return;
  }
  if ([...next].length < 8) {
    message.textContent = "Password must be at least 8 characters.";
    message.className = "error-text";
    return;
  }

  const button = event.submitter || $("password-submit");
  button.disabled = true;
  try {
    await api("/api/auth/password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        current: $("password-current").value,
        new: next,
      }),
    });
    $("password-current").value = "";
    $("password-new").value = "";
    $("password-confirm").value = "";
    message.textContent = "Password changed. Other sessions were signed out.";
    message.className = "hint";
  } catch (error) {
    message.textContent = error.message;
    message.className = "error-text";
  } finally {
    button.disabled = false;
  }
}

async function generateToken() {
  const button = $("generate-token");
  button.disabled = true;
  const message = $("token-message");
  try {
    const issued = await api("/api/auth/token", { method: "POST" });
    $("token-value").value = issued.token;
    $("token-once").classList.remove("hidden");
    $("copy-token").textContent = "Copy";
    message.textContent = "Copy this token now. It will not be shown again.";
    message.className = "hint";
  } catch (error) {
    message.textContent = error.message;
    message.className = "error-text";
  } finally {
    button.disabled = false;
  }
}

async function revokeToken() {
  const message = $("token-message");
  try {
    await api("/api/auth/token", { method: "DELETE" });
    $("token-value").value = "";
    $("token-once").classList.add("hidden");
    message.textContent = "API token revoked.";
    message.className = "hint";
  } catch (error) {
    message.textContent = error.message;
    message.className = "error-text";
  }
}

async function copyToken() {
  const input = $("token-value");
  input.focus();
  input.select();
  try {
    await navigator.clipboard.writeText(input.value);
    $("copy-token").textContent = "Copied";
  } catch (_) {
    $("copy-token").textContent = "Copy";
  }
}
