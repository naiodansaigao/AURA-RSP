#!/usr/bin/env python3
"""Generate a private RSP test PKI from Osmocom's upstream generator.

The upstream SGP.26-derived TLS validity window ends in 2025 in the generator
source. This wrapper changes only the local test TLS certificate end date to
2035. It does not alter ES9+/ES8+ protocol or authentication code.
"""

from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
PYSIM = ROOT / "third_party" / "pysim"
UPSTREAM = PYSIM / "contrib" / "generate_smdpp_certs.py"
RUNTIME = ROOT / "runtime"
PATCHED = RUNTIME / "generate_smdpp_certs_runtime.py"


def main() -> None:
    source = UPSTREAM.read_text(encoding="utf-8")
    old = "datetime(2025, 8, 11, 15, 29, 36)"
    new = "datetime(2035, 8, 11, 15, 29, 36)"
    if old not in source:
        raise SystemExit("Upstream TLS validity marker changed; inspect generator before continuing.")

    RUNTIME.mkdir(parents=True, exist_ok=True)
    PATCHED.write_text(source.replace(old, new), encoding="utf-8")

    generated = PYSIM / "smdpp-data" / "generated"
    if generated.exists():
        shutil.rmtree(generated)

    subprocess.run([sys.executable, str(PATCHED)], cwd=PYSIM, check=True)

    required = [
        generated / "CertificateIssuer" / "CERT_CI_ECDSA_NIST.pem",
        generated / "DPtls" / "CERT_S_SM_DP_TLS_NIST.der",
        generated / "DPtls" / "SK_S_SM_DP_TLS_NIST.pem",
        generated / "DPauth" / "CERT_S_SM_DPauth_ECDSA_NIST.der",
        generated / "DPpb" / "CERT_S_SM_DPpb_ECDSA_NIST.der",
        generated / "EUM" / "CERT_EUM_ECDSA_NIST.der",
        generated / "eUICC" / "CERT_EUICC_ECDSA_NIST.der",
        generated / "eUICC" / "SK_EUICC_ECDSA_NIST.pem",
    ]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise SystemExit("PKI generation incomplete:\n" + "\n".join(missing))

    print(f"TEST_PKI_OK={generated}")


if __name__ == "__main__":
    main()

