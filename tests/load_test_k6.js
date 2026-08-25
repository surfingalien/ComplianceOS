import http from "k6/http";
import { check, sleep } from "k6";

export const options = {
  vus: 10,
  duration: "30s",
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<800"],
  },
};

const BASE = "http://localhost:8000";

export default function () {
  const health = http.get(`${BASE}/health`);
  check(health, { "health 200": r => r.status === 200 });

  const metrics = http.get(`${BASE}/v1/brain/metrics`);
  check(metrics, { "metrics 200": r => r.status === 200 });

  const controls = http.get(`${BASE}/v1/controls`);
  check(controls, { "controls 200": r => r.status === 200 });

  sleep(1);
}
