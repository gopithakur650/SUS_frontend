# SUSignal Sample Configurations

This directory provides realistic, simulated 5G Core Network Function (NF) configuration files in both YAML and JSON formats. These can be used to test the SUSignal scanning engine, API upload endpoints, and web dashboard.

---

## Included Sample Files

| File | Network Function | Format | Security Posture | Description |
| :--- | :--- | :--- | :--- | :--- |
| `amf_vulnerable.yaml` | AMF | YAML | **Vulnerable** | Contains null ciphering (`NEA0`), unencrypted SBI (`http`), and wildcard (`0.0.0.0`) bindings. |
| `amf_hardened.yaml` | AMF | YAML | **Hardened (Secure)** | Uses strong cryptographic ciphers (`NEA2`, `NIA2`), TLS 1.3 encryption on SBI, and explicit IP interfaces. |
| `smf_sample.json` | SMF | JSON | **Vulnerable** | Demonstrates JSON-formatted configuration with unencrypted SBI and open interfaces. |

---

## Future Integrations Note

These simulated files mirror common 5G Core parameters (such as PLMN, TAI, SBI, and crypto algorithms). 

In Phase 2, when Open5GS and free5GC integrations are implemented:
- Actual `.yaml` files from Open5GS (e.g. `/etc/open5gs/*.yaml`)
- Actual configuration dumps from free5GC (e.g. `config/*.yaml`)

will be loaded directly via the `backend/app/integrations` pipeline adapters.
