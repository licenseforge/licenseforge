// Preloaded by sdk_test.go (node --import): <ip>.nip.io names resolve to the
// address they carry, without DNS, as the Go journeys dial them. nip.io is a
// public service, and some resolvers drop answers pointing at private addresses.
import dns from "node:dns";

const lookup = dns.lookup;
dns.lookup = (host, opts, cb) => {
  const m = /(?:^|\.)(\d{1,3}(?:\.\d{1,3}){3})\.nip\.io$/.exec(host);
  if (!m) return lookup(host, opts, cb);
  if (typeof opts === "function") [cb, opts] = [opts, {}];
  if (opts?.all) return process.nextTick(cb, null, [{ address: m[1], family: 4 }]);
  process.nextTick(cb, null, m[1], 4);
};
