// This file represents JavaScript shipped to an ordinary portal user.
// The explorer treats it as text; it never executes discovered code.

async function loadCatalog() {
  return fetch("/api/catalog");
}

async function loadMe() {
  return fetch("/api/me");
}

async function loadUser(userId) {
  return fetch(`/api/users/${userId}`);
}

// Left behind by an unfinished staff screen; neither route is in OpenAPI.
async function loadAuditForStaff() {
  return fetch("/api/admin/audit");
}

async function loadDebugPanel() {
  return fetch("/api/debug/config");
}

