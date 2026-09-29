/** In-memory auth token bridge — no React, no storage. */

let _tokenGetter: (() => string | null) | null = null;

export function registerAuthTokenGetter(getter: () => string | null) {
  _tokenGetter = getter;
}

export function getAuthToken(): string | null {
  return _tokenGetter ? _tokenGetter() : null;
}
