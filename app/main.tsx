import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { ZaspApp } from "./components/ZaspApp";
import "./globals.css";

const root = document.getElementById("root");

if (!root) {
  throw new Error("Zasp application root element is missing.");
}

createRoot(root).render(
  <StrictMode>
    <ZaspApp />
  </StrictMode>,
);
