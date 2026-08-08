/* global AV */
var AV = (function () {
  'use strict';

  function csrfToken() {
    var match = document.cookie.match(/(?:^|;\s*)agent_vault_csrf=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : '';
  }

  function apiFetch(path, options) {
    options = options || {};
    var headers = Object.assign({ 'Accept': 'application/json' }, options.headers || {});
    if (options.body && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }
    var method = (options.method || 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'HEAD') {
      headers['X-CSRF-Token'] = csrfToken();
    }
    return fetch(path, {
      method: method,
      headers: headers,
      body: options.body,
      credentials: 'same-origin'
    });
  }

  function showError(el, message) {
    if (!el) return;
    el.textContent = message;
    el.hidden = !message;
    if (message) {
      el.classList.add('error');
      el.classList.remove('info');
    }
  }

  function showInfo(el, message) {
    if (!el) return;
    el.textContent = message;
    el.hidden = !message;
    if (message) {
      el.classList.add('info');
      el.classList.remove('error');
    }
  }

  function clearMessage(el) {
    if (!el) return;
    el.textContent = '';
    el.hidden = true;
    el.classList.remove('error');
    el.classList.remove('info');
  }

  function formatTime(value) {
    if (!value) return '';
    try {
      return new Date(value).toLocaleString();
    } catch (e) {
      return String(value);
    }
  }

  function tagsToString(tags) {
    return Array.isArray(tags) ? tags.join(', ') : '';
  }

  function parseTags(value) {
    if (!value || !value.trim()) return [];
    return value.split(',').map(function (t) { return t.trim(); }).filter(Boolean);
  }

  function updateVaultChrome(data) {
    var statusEl = document.getElementById('vault-status');
    var bannerEl = document.getElementById('sealed-banner');
    var lockBtn = document.getElementById('btn-lock');
    var unlockBtn = document.getElementById('btn-unlock');
    if (!data || !statusEl) return;
    statusEl.textContent = data.sealed ? 'Sealed' : 'Unlocked';
    statusEl.classList.toggle('sealed', !!data.sealed);
    if (bannerEl) bannerEl.hidden = !data.sealed;
    if (lockBtn) lockBtn.hidden = !!data.sealed;
    if (unlockBtn) unlockBtn.hidden = !data.sealed;
  }

  function refreshVaultStatus() {
    return apiFetch('/ui/api/status').then(function (resp) {
      if (!resp.ok) {
        if (resp.status === 401) {
          window.location.href = '/ui/login';
        }
        return null;
      }
      return resp.json();
    }).then(function (data) {
      if (data) updateVaultChrome(data);
      return data;
    });
  }

  function initAppChrome() {
    var lockBtn = document.getElementById('btn-lock');
    var unlockBtn = document.getElementById('btn-unlock');
    var logoutBtn = document.getElementById('btn-logout');

    refreshVaultStatus();

    if (lockBtn) {
      lockBtn.addEventListener('click', function () {
        apiFetch('/ui/api/lock', { method: 'POST' }).then(function (resp) {
          if (resp.ok) {
            window.location.reload();
          }
        });
      });
    }

    if (unlockBtn) {
      unlockBtn.addEventListener('click', function () {
        var passphrase = window.prompt('Enter vault passphrase to unlock:');
        if (!passphrase) return;
        apiFetch('/ui/api/unlock', {
          method: 'POST',
          body: JSON.stringify({ passphrase: passphrase })
        }).then(function (resp) {
          return resp.json().then(function (data) {
            return { ok: resp.ok, data: data };
          });
        }).then(function (result) {
          if (result.ok) {
            window.location.reload();
            return;
          }
          window.alert((result.data && result.data.error) || 'Unlock failed');
        }).catch(function () {
          window.alert('Unlock failed');
        });
      });
    }

    if (logoutBtn) {
      logoutBtn.addEventListener('click', function () {
        apiFetch('/ui/logout', { method: 'POST' }).then(function () {
          window.location.href = '/ui/login';
        });
      });
    }

    var cpForm = document.getElementById('change-passphrase-form');
    if (cpForm) {
      cpForm.addEventListener('submit', function (ev) {
        ev.preventDefault();
        var oldEl = document.getElementById('cp-old');
        var newEl = document.getElementById('cp-new');
        var confirmEl = document.getElementById('cp-confirm');
        var statusEl = document.getElementById('cp-status');
        var oldPass = oldEl ? oldEl.value : '';
        var newPass = newEl ? newEl.value : '';
        var confirmPass = confirmEl ? confirmEl.value : '';
        if (!oldPass || !newPass) {
          if (statusEl) statusEl.textContent = 'Both passphrases are required.';
          return;
        }
        if (newPass !== confirmPass) {
          if (statusEl) statusEl.textContent = 'New passphrase and confirmation do not match.';
          return;
        }
        if (statusEl) statusEl.textContent = 'Updating…';
        apiFetch('/ui/api/change-passphrase', {
          method: 'POST',
          body: JSON.stringify({ old_passphrase: oldPass, new_passphrase: newPass })
        }).then(function (resp) {
          return resp.json().then(function (data) {
            return { ok: resp.ok, data: data };
          });
        }).then(function (result) {
          if (result.ok) {
            if (oldEl) oldEl.value = '';
            if (newEl) newEl.value = '';
            if (confirmEl) confirmEl.value = '';
            var msg = 'Passphrase updated. All agent tokens revoked.';
            if (result.data && typeof result.data.token === 'string' && result.data.token) {
              msg += ' New root token (save now): ' + result.data.token;
            }
            if (statusEl) statusEl.textContent = msg;
            return;
          }
          var errMsg = 'Update failed';
          if (result.data && typeof result.data.error === 'string') {
            errMsg = result.data.error;
          }
          if (statusEl) statusEl.textContent = errMsg;
        }).catch(function () {
          if (statusEl) statusEl.textContent = 'Update failed';
        });
      });
    }

    var rmForm = document.getElementById('rotate-master-form');
    if (rmForm) {
      rmForm.addEventListener('submit', function (ev) {
        ev.preventDefault();
        var passEl = document.getElementById('rm-pass');
        var statusEl = document.getElementById('rm-status');
        var pass = passEl ? passEl.value : '';
        if (!pass) {
          if (statusEl) statusEl.textContent = 'Passphrase is required.';
          return;
        }
        if (!window.confirm('Rotate the master key? This rewrites unseal.key and revokes all agent tokens.')) {
          return;
        }
        if (statusEl) statusEl.textContent = 'Rotating…';
        apiFetch('/ui/api/rotate-master', {
          method: 'POST',
          body: JSON.stringify({ passphrase: pass })
        }).then(function (resp) {
          return resp.json().then(function (data) {
            return { ok: resp.ok, data: data };
          });
        }).then(function (result) {
          if (result.ok) {
            if (passEl) passEl.value = '';
            var msg = 'Master key rotated. All agent tokens revoked.';
            if (result.data && typeof result.data.token === 'string' && result.data.token) {
              msg += ' New root token (save now): ' + result.data.token;
            }
            if (statusEl) statusEl.textContent = msg;
            return;
          }
          var errMsg = 'Rotate failed';
          if (result.data && typeof result.data.error === 'string') {
            errMsg = result.data.error;
          }
          if (statusEl) statusEl.textContent = errMsg;
        }).catch(function () {
          if (statusEl) statusEl.textContent = 'Rotate failed';
        });
      });
    }
  }

  function initLoginPage() {
    var form = document.getElementById('login-form');
    var errorEl = document.getElementById('login-error');
    var vaultStatusEl = document.getElementById('login-vault-status');
    if (!form) return;

    if (vaultStatusEl) {
      apiFetch('/health').then(function (resp) {
        if (!resp.ok) return null;
        return resp.json();
      }).then(function (data) {
        if (!data) return;
        var sealed = !!data.sealed;
        vaultStatusEl.textContent = sealed ? 'Vault status: Sealed' : 'Vault status: Unsealed';
        vaultStatusEl.classList.toggle('sealed', sealed);
      }).catch(function () {});
    }

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      clearMessage(errorEl);
      var passphrase = document.getElementById('passphrase').value;
      apiFetch('/ui/login', {
        method: 'POST',
        body: JSON.stringify({ passphrase: passphrase })
      }).then(function (resp) {
        return resp.json().then(function (data) {
          return { ok: resp.ok, status: resp.status, data: data };
        });
      }).then(function (result) {
        if (result.ok) {
          window.location.href = '/ui/';
          return;
        }
        showError(errorEl, (result.data && result.data.error) || 'Login failed');
      }).catch(function () {
        showError(errorEl, 'Login failed');
      });
    });
  }

  function renderSecretsTable(tbody, secrets) {
    if (!tbody) return;
    if (!secrets.length) {
      var emptyMsg = 'No secrets found.';
      if (!window._avListHasQuery) {
        emptyMsg = 'No secrets yet. <a href="/ui/secrets/new">Create one</a>.';
      }
      tbody.innerHTML = '<tr><td colspan="4" class="text-muted">' + emptyMsg + '</td></tr>';
      return;
    }
    tbody.innerHTML = secrets.map(function (sec) {
      var name = sec.name || '';
      var href = '/ui/s/' + encodeURIComponent(name);
      return '<tr>' +
        '<td><a href="' + href + '">' + escapeHtml(name) + '</a></td>' +
        '<td>' + escapeHtml(sec.type || '') + '</td>' +
        '<td>' + escapeHtml(tagsToString(sec.tags)) + '</td>' +
        '<td>' + escapeHtml(formatTime(sec.updated_at)) + '</td>' +
        '</tr>';
    }).join('');
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function loadSecrets(query) {
    var tbody = document.getElementById('secrets-body');
    var messageEl = document.getElementById('list-message');
    clearMessage(messageEl);
    var path = '/ui/api/secrets';
    window._avListHasQuery = !!(query && (query.q || query.tag || query.type));
    if (window._avListHasQuery) {
      var params = new URLSearchParams();
      if (query.q) params.set('q', query.q);
      if (query.tag) params.set('tag', query.tag);
      if (query.type) params.set('type', query.type);
      path = '/ui/api/search?' + params.toString();
    }
    apiFetch(path).then(function (resp) {
      if (resp.status === 401) {
        window.location.href = '/ui/login';
        return null;
      }
      if (!resp.ok) {
        return resp.json().then(function (data) {
          showError(messageEl, (data && data.error) || 'Failed to load secrets');
          return null;
        });
      }
      return resp.json();
    }).then(function (data) {
      if (data) {
        renderSecretsTable(tbody, data);
      }
    });
  }

  function initListPage() {
    var form = document.getElementById('search-form');
    var clearBtn = document.getElementById('search-clear');
    loadSecrets();

    if (form) {
      form.addEventListener('submit', function (e) {
        e.preventDefault();
        loadSecrets({
          q: document.getElementById('search-q').value,
          tag: document.getElementById('search-tag').value,
          type: document.getElementById('search-type').value
        });
      });
    }

    if (clearBtn) {
      clearBtn.addEventListener('click', function () {
        document.getElementById('search-q').value = '';
        document.getElementById('search-tag').value = '';
        document.getElementById('search-type').value = '';
        loadSecrets();
      });
    }
  }

  function renderDetail(sec, revealed) {
    var content = document.getElementById('detail-content');
    if (!content) return;
    var secretValue = revealed && sec.secret ? escapeHtml(sec.secret) : 'Hidden';
    var usernameRow = sec.username ? (
      '<div class="detail-row"><dt>Username</dt><dd>' + escapeHtml(sec.username) + '</dd></div>'
    ) : '';
    content.innerHTML =
      '<dl class="detail-grid">' +
      '<div class="detail-row"><dt>Type</dt><dd>' + escapeHtml(sec.type || '') + '</dd></div>' +
      '<div class="detail-row"><dt>Secret</dt><dd id="secret-value">' + secretValue + '</dd></div>' +
      usernameRow +
      '<div class="detail-row"><dt>URL</dt><dd>' + escapeHtml(sec.url || '') + '</dd></div>' +
      '<div class="detail-row"><dt>Tags</dt><dd>' + escapeHtml(tagsToString(sec.tags)) + '</dd></div>' +
      '<div class="detail-row"><dt>Notes</dt><dd>' + escapeHtml(sec.notes || '') + '</dd></div>' +
      '<div class="detail-row"><dt>Updated</dt><dd>' + escapeHtml(formatTime(sec.updated_at)) + '</dd></div>' +
      '</dl>';
    content._secretData = sec;
    content._revealed = revealed;
  }

  function initDetailPage() {
    var content = document.getElementById('detail-content');
    var messageEl = document.getElementById('detail-message');
    var revealBtn = document.getElementById('btn-reveal');
    var copyBtn = document.getElementById('btn-copy');
    var editBtn = document.getElementById('btn-edit');
    var deleteBtn = document.getElementById('btn-delete');
    var editForm = document.getElementById('edit-form');
    var editCancel = document.getElementById('edit-cancel');
    if (!content) return;

    var name = content.getAttribute('data-secret-name');

    function loadDetail(reveal) {
      clearMessage(messageEl);
      var path = '/ui/api/secrets/' + encodeURIComponent(name);
      if (reveal) path += '?reveal=1';
      apiFetch(path).then(function (resp) {
        if (resp.status === 401) {
          window.location.href = '/ui/login';
          return null;
        }
        if (!resp.ok) {
          return resp.json().then(function (data) {
            showError(messageEl, (data && data.error) || 'Failed to load secret');
            return null;
          });
        }
        return resp.json();
      }).then(function (data) {
        if (data) {
          renderDetail(data, reveal);
          if (copyBtn) copyBtn.disabled = !reveal;
        }
      });
    }

    loadDetail(false);

    if (revealBtn) {
      revealBtn.addEventListener('click', function () {
        loadDetail(true);
      });
    }

    if (copyBtn) {
      copyBtn.addEventListener('click', function () {
        var data = content._secretData;
        if (!data || !data.secret) return;
        navigator.clipboard.writeText(data.secret).catch(function () {});
      });
    }

    if (editBtn && editForm) {
      editBtn.addEventListener('click', function () {
        function populateEditForm(data) {
          var typeEl = document.getElementById('edit-type');
          var typeVal = data.type || 'api_key';
          if (typeEl) typeEl.value = typeVal;
          document.getElementById('edit-secret').value = data.secret || '';
          document.getElementById('edit-username').value = data.username || '';
          document.getElementById('edit-url').value = data.url || '';
          document.getElementById('edit-tags').value = tagsToString(data.tags);
          document.getElementById('edit-notes').value = data.notes || '';
          editForm.hidden = false;
        }

        if (content._revealed && content._secretData && content._secretData.secret) {
          populateEditForm(content._secretData);
          return;
        }

        clearMessage(messageEl);
        editBtn.disabled = true;
        apiFetch('/ui/api/secrets/' + encodeURIComponent(name) + '?reveal=1').then(function (resp) {
          if (resp.status === 401) {
            window.location.href = '/ui/login';
            return null;
          }
          if (!resp.ok) {
            return resp.json().then(function (data) {
              showError(messageEl, (data && data.error) || 'Failed to reveal secret for editing');
              return null;
            });
          }
          return resp.json();
        }).then(function (data) {
          if (!data) return;
          renderDetail(data, true);
          if (copyBtn) copyBtn.disabled = false;
          showInfo(messageEl, 'Secret revealed for editing.');
          populateEditForm(data);
        }).catch(function () {
          showError(messageEl, 'Failed to reveal secret for editing');
        }).finally(function () {
          editBtn.disabled = false;
        });
      });
    }

    if (editCancel && editForm) {
      editCancel.addEventListener('click', function () {
        editForm.hidden = true;
      });
    }

    if (editForm) {
      editForm.addEventListener('submit', function (e) {
        e.preventDefault();
        clearMessage(messageEl);
        var body = {
          type: document.getElementById('edit-type').value,
          secret: document.getElementById('edit-secret').value,
          username: document.getElementById('edit-username').value,
          url: document.getElementById('edit-url').value,
          tags: parseTags(document.getElementById('edit-tags').value),
          notes: document.getElementById('edit-notes').value
        };
        apiFetch('/ui/api/secrets/' + encodeURIComponent(name), {
          method: 'PUT',
          body: JSON.stringify(body)
        }).then(function (resp) {
          if (!resp.ok) {
            return resp.json().then(function (data) {
              showError(messageEl, (data && data.error) || 'Update failed');
            });
          }
          editForm.hidden = true;
          loadDetail(false);
        });
      });
    }

    if (deleteBtn) {
      deleteBtn.addEventListener('click', function () {
        if (!window.confirm('Delete secret "' + name + '"?')) return;
        apiFetch('/ui/api/secrets/' + encodeURIComponent(name), {
          method: 'DELETE'
        }).then(function (resp) {
          if (resp.ok || resp.status === 204) {
            window.location.href = '/ui/';
            return;
          }
          return resp.json().then(function (data) {
            showError(messageEl, (data && data.error) || 'Delete failed');
          });
        });
      });
    }
  }

  function initNewPage() {
    var form = document.getElementById('new-form');
    var errorEl = document.getElementById('new-error');
    if (!form) return;

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      clearMessage(errorEl);
      var body = {
        name: document.getElementById('new-name').value,
        type: document.getElementById('new-type').value,
        secret: document.getElementById('new-secret').value,
        username: document.getElementById('new-username').value,
        url: document.getElementById('new-url').value,
        tags: parseTags(document.getElementById('new-tags').value),
        notes: document.getElementById('new-notes').value
      };
      apiFetch('/ui/api/secrets', {
        method: 'POST',
        body: JSON.stringify(body)
      }).then(function (resp) {
        return resp.json().then(function (data) {
          return { ok: resp.ok, data: data };
        });
      }).then(function (result) {
        if (result.ok) {
          var createdName = result.data && result.data.name;
          window.location.href = '/ui/s/' + encodeURIComponent(createdName || body.name);
          return;
        }
        showError(errorEl, (result.data && result.data.error) || 'Create failed');
      }).catch(function () {
        showError(errorEl, 'Create failed');
      });
    });
  }

  function initAuditPage() {
    var tbody = document.getElementById('audit-body');
    var messageEl = document.getElementById('audit-message');
    clearMessage(messageEl);

    apiFetch('/ui/api/audit').then(function (resp) {
      if (resp.status === 401) {
        window.location.href = '/ui/login';
        return null;
      }
      if (!resp.ok) {
        return resp.json().then(function (data) {
          showError(messageEl, (data && data.error) || 'Failed to load audit log');
          return null;
        });
      }
      return resp.json();
    }).then(function (rows) {
      if (!tbody || !rows) return;
      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-muted">No audit events.</td></tr>';
        return;
      }
      tbody.innerHTML = rows.map(function (row) {
        return '<tr>' +
          '<td>' + escapeHtml(formatTime(row.timestamp)) + '</td>' +
          '<td>' + escapeHtml(row.token_label || '') + '</td>' +
          '<td>' + escapeHtml(row.action || '') + '</td>' +
          '<td>' + escapeHtml(row.secret_name || '') + '</td>' +
          '</tr>';
      }).join('');
    });
  }

  return {
    initAppChrome: initAppChrome,
    initLoginPage: initLoginPage,
    initListPage: initListPage,
    initDetailPage: initDetailPage,
    initNewPage: initNewPage,
    initAuditPage: initAuditPage
  };
})();
