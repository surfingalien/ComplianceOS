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

export default function () {
  const metrics = http.get("http://localhost:8000/v1/brain/metrics");

  check(metrics, {
    "metrics status is 200": (r) => r.status === 200,
  });

  const health = http.get("http://localhost:8000/v1/brain/health");

  check(health, {
    "brain health status is 200": (r) => r.status === 200,
  });

  sleep(1);
}
