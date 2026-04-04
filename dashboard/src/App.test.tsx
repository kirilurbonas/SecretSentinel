import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "./auth";
import App from "./App";

// Stub out the Secrets page so it doesn't need real API calls
vi.mock("./pages/Secrets", () => ({
  default: () => <div data-testid="secrets-page">Secrets Page</div>,
}));

vi.mock("./pages/Login", () => ({
  default: () => <div data-testid="login-page">Login Page</div>,
}));

function renderApp(initialEntries = ["/"]) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe("App routing", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("redirects unauthenticated users to /login from /", () => {
    renderApp(["/"]);
    expect(screen.getByTestId("login-page")).toBeInTheDocument();
  });

  it("redirects unauthenticated users to /login from /secrets", () => {
    renderApp(["/secrets"]);
    expect(screen.getByTestId("login-page")).toBeInTheDocument();
  });

  it("redirects unknown routes to login when unauthenticated", () => {
    renderApp(["/unknown-route"]);
    expect(screen.getByTestId("login-page")).toBeInTheDocument();
  });

  it("shows secrets page when authenticated", () => {
    localStorage.setItem("sentinel_token", "test-jwt-token.payload.sig");
    renderApp(["/secrets"]);
    expect(screen.getByTestId("secrets-page")).toBeInTheDocument();
  });

  it("shows the app header with brand name when authenticated", () => {
    localStorage.setItem("sentinel_token", "test-jwt-token.payload.sig");
    renderApp(["/secrets"]);
    expect(screen.getByText("SecretSentinel")).toBeInTheDocument();
  });

  it("shows sign out button when authenticated", () => {
    localStorage.setItem("sentinel_token", "test-jwt-token.payload.sig");
    renderApp(["/secrets"]);
    expect(screen.getByRole("button", { name: /sign out/i })).toBeInTheDocument();
  });
});

describe("Auth flow", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("logout button clears token and redirects to login", async () => {
    const user = userEvent.setup();
    localStorage.setItem("sentinel_token", "test-jwt-token.payload.sig");
    renderApp(["/secrets"]);

    const signOutBtn = screen.getByRole("button", { name: /sign out/i });
    await user.click(signOutBtn);

    expect(localStorage.getItem("sentinel_token")).toBeNull();
  });
});
