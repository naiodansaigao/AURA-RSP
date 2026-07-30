# GitHub release checklist

Before making the repository public:

- [ ] Replace `<YOUR_REPOSITORY_URL>` in the root README.
- [ ] Copy `CITATION.cff.example` to `CITATION.cff` and fill in authors, paper
      title, DOI, and repository URL.
- [ ] Select a license for the original AURA-RSP and experiment code; replace
      `LICENSE-NOTICE.md` with the chosen license or add an explicit research
      artifact license.
- [ ] Keep all upstream license files and `THIRD_PARTY_NOTICES.md`.
- [ ] Run `python3 scripts/build_manifest.py`.
- [ ] Run `python3 scripts/verify_artifact.py`.
- [ ] Run `sha256sum -c MANIFEST.sha256`.
- [ ] Run the Standard baseline and AURA demo on a clean WSL2 Ubuntu 24.04
      installation.
- [ ] Run all thirteen experiments and archive the console output.
- [ ] Run Experiment 13 with `--backend production`; do not cite the portable
      backend as BBS+ evidence.
- [ ] Confirm that no real subscriber identity, production Profile, production
      certificate, API token, or private deployment key is present.
- [ ] Create a versioned release tag, for example `artifact-v1.0.0`.

