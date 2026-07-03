# LayerZero V2 OFT Bug Lab

Educational lab for invariant-break scenarios around LayerZero V2 OFT-style token flows.

This repository is not a claim about historical production vulnerabilities. It is a local security lab built to practice:

- invariant reasoning
- bridge-path breakage
- exploit-style PoC tests
- audit-style reporting

## Scope

This lab focuses on contract-layer OFT logic:

- source-side debit/accounting
- message construction
- destination-side credit
- trusted peer assumptions
- options / compose handling assumptions

## Structure

- `audit-report.md` - writeup for each lab bug
- `src/VulnerableOApp.sol` - vulnerable toy OFT-like contract
- `test/OAppExploits.t.sol` - PoC tests
- `foundry.toml` - Foundry config

## Bug Set

1. Amount Consistency Break
2. Peer Validation Bypass At External Receive Boundary
3. Zero-Address Context Hijacking At Credit Step
4. Unauthorized Peer Mutation
5. Slippage Check Bypass In `_debitView(...)`

## Usage

```bash
forge test
```
