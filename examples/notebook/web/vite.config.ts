import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// `falak dev` listens on 8787. Proxying keeps the browser on one origin, so the API
// needs no CORS settings.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/v1": "http://127.0.0.1:8787",
    },
  },
});
