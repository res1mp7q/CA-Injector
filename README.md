# Excelsior FreeIPA CA Injector

The **Excelsior CA Injector** is a Certificate installer that pulls the current **FreeIPA Certificate Authority (CA)** from your identity infrastructure and installs it into any **Ubuntu/Debian** system's trust store.

This is designed for internal use across FreeIPA managed fleets, air-gapped labs, retro racks, and edge nodes that require trusted communication with core CA-backed services.

---

## One-Line Install

Run this on any host to inject the FreeIPA Root CA on you Debian or Ubuntu hosts:

```bash
curl -s -L http://inject.ex777.us | bash

