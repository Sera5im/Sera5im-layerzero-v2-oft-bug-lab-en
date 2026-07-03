# Audit Report

## 1. Amount Consistency Break

### Invariant

The source-side accounting result must stay consistent with the amount carried into outbound / inbound semantics.

### What this means

The amount actually processed on the source side must match the amount later encoded into the outbound message and credited on the destination side.

### Safe logic

```solidity
amountSentLD = _removeDust(_amountLD);
amountReceivedLD = amountSentLD;
```

### Vulnerable modification

```solidity
amountSentLD = _removeDust(_amountLD);
amountReceivedLD = _amountLD;
```

### Affected path

`_debitView(...) -> _debit(...) -> _buildMessage(...) -> _lzReceive(...) -> _credit(...)`

### Attack outcome

The source-side path processes one amount, while the destination-side path credits another.

### Why this matters

This breaks bridge transfer semantics between source-side accounting and destination-side credit.

### Test

`test_AmountConsistencyBreak_InflatesRemoteCredit()`

## 2. Peer Validation Bypass At External Receive Boundary

### Invariant

The receive entrypoint must not accept a message unless the remote sender matches the trusted peer configured for the selected source eid.

### What this means

Checking only the local endpoint caller is not enough. The receive path must also verify that the remote sender for `srcEid` is the expected trusted peer.

### Safe logic

```solidity
function lzReceive(
    uint32 srcEid,
    bytes32 sender,
    bytes calldata message
) external {
    if (msg.sender != endpoint) revert NotEndpoint();
    if (_getPeerOrRevert(srcEid) != sender) revert InvalidPeer();

    _lzReceive(message);
}
```

### Vulnerable modification

```solidity
function lzReceive(
    uint32 srcEid,
    bytes32 sender,
    bytes calldata message
) external {
    if (msg.sender != endpoint) revert NotEndpoint();

    _lzReceive(message);
}
```

### Affected path

`lzReceive(...) -> _lzReceive(...) -> _credit(...)`

### Attack outcome

An attacker can inject a fake inbound message through the external receive entrypoint as long as the call appears to come from the endpoint, even though the remote sender is not the trusted peer.

### Why this matters

This breaks the receive-side trust boundary. The contract accepts unauthorized cross-chain message semantics and credits attacker-controlled state on the destination side.

### Test

`test_LzReceive_BypassesPeerValidation_InflatesAttackerBalance()`

## 3. Zero-Address Context Hijacking At Credit Step

### Invariant

Zero-address recipient handling must not fall back to caller-controlled recipient semantics.

### What this means

If the decoded receive-side recipient is `address(0)`, the credit path must not silently replace it with caller context such as `msg.sender`.

### Safe logic

```solidity
if (to == address(0)) {
    to = address(0xdead);
}
```

### Vulnerable modification

```solidity
if (to == address(0)) {
    to = msg.sender;
}
```

### Affected path

`lzReceive(...) -> _lzReceive(...) -> _credit(...)`

### Attack outcome

A zero-address recipient in the inbound message can be redirected into caller-context credit, causing the destination-side balance to be assigned to `endpoint` instead of a neutral sink.

### Why this matters

This breaks recipient semantics at the destination-side credit step. The credited recipient is no longer determined only by the message payload.

### Test

`test_ZeroAddressContextHijacking_CreditsCallerContext()`

## 4. Unauthorized Peer Mutation

### Invariant

Peer configuration must not be mutable by arbitrary users.

### What this means

The trusted peer for a selected eid is part of the receive-side trust boundary. It must not be rewritable by unprivileged callers.

### Safe logic

```solidity
function setPeer(uint32 eid, bytes32 peer) external {
    if (msg.sender != owner) revert NotOwner();
    peers[eid] = peer;
}
```

### Vulnerable modification

```solidity
function setPeer(uint32 eid, bytes32 peer) external {
    peers[eid] = peer;
}
```

### Affected path

`setPeer(...) -> lzReceive(...) -> _lzReceive(...) -> _credit(...)`

### Attack outcome

An attacker can overwrite the trusted peer for a selected eid, then send an attacker-controlled message that passes receive-side peer validation and credits attacker-controlled state.

### Why this matters

This breaks the configuration-side trust boundary that the receive path depends on. The contract may appear to enforce peer validation, but that validation becomes meaningless if arbitrary users can rewrite the trusted peer.

### Test

`test_UnauthorizedPeerMutation_AllowsAttackerControlledReceive()`

## 5. Slippage Check Bypass In `_debitView(...)`

### Invariant

The slippage guard must be enforced against the final normalized receive amount, not against the pre-normalization input amount.

### What this means

If the bridge normalizes the amount before crediting the destination side, then `minAmountLD` must be checked against that normalized result. Otherwise the transfer may succeed even though the user receives less than the declared minimum.

### Safe logic

```solidity
amountSentLD = _removeDust(amountLD);
amountReceivedLD = amountSentLD;

if (amountReceivedLD < minAmountLD) {
    revert SlippageExceeded(amountReceivedLD, minAmountLD);
}
```

### Vulnerable modification

```solidity
if (amountLD < minAmountLD) {
    revert SlippageExceeded(amountLD, minAmountLD);
}

amountSentLD = _removeDust(amountLD);
amountReceivedLD = amountSentLD;
```

### Affected path

`_debitView(...) -> _debit(...) -> _buildMessage(...) -> _lzReceive(...) -> _credit(...)`

### Attack outcome

The send path accepts an input that appears to satisfy the user minimum, but after normalization the final credited amount drops below `minAmountLD` and still succeeds.

### Why this matters

This breaks the user-side minimum receive guarantee. The protocol claims to protect against slippage, but the check is attached to the wrong amount.

### Test

`test_MinAmountCheckBeforeNormalization_AllowsLessThanMinAmount()`
