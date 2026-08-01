# Experiment 12: PR Source-Address Privacy and PR–SM-DP+ Collusion

- Status: **PASS**
- Devices: 100
- Transactions per device: 4
- Machine assertions: 15/15

## Network modes

| Metric | 12A Direct | 12B Shared PR |
|---|---:|---:|
| Source addresses visible to SM-DP+ | 100 | 1 |
| IP-only ROC-AUC | 1.0000 | 0.5000 |
| Pairwise balanced accuracy | 1.0000 | 0.5000 |
| Mean device anonymity set | 1.00 | 100.00 |
| Exact device-history recovery | 1.0000 | 0.0000 |
| Expected device identification from IP | 1.0000 | 0.0100 |

## 12C Collusion

| Matcher | Transaction accuracy | False-match rate | Full device-history recovery |
|---|---:|---:|---:|
| Time only | 0.8150 | 0.1850 | 0.4700 |
| Time and flow size | 0.9950 | 0.0050 | 0.9800 |

## Conclusion

With direct connections, a stable source IP helps the SM-DP+ recover cross-
transaction device history. A shared PR places all devices in one source-address
anonymity set and reduces IP-only linkage to random performance. When the PR and
SM-DP+ collude, timing and flow-size metadata can relink connections.

12C is an expected privacy failure at the explicitly stated threat-model
boundary, not a flaw in AURA authentication or Profile delivery. The numeric
result comes from a fixed-seed controlled metadata trace, not a claim about an
absolute real-Internet anonymity level.
