# Held-Out Ground Truth Labels

| File | Variant | Expected Eligible Findings | Ground Truth Rationale |
|---|---|---|---|
| `h1.sol` | Multi-hop reentrancy | `R: H1.take(uint256)`, path: `[H1.take(uint256)]` | `take(uint256)` calls `_pay` which executes external low-level call before state variable `bal` is updated (checks-effects-interactions violation). |
| `h2.sol` | Renamed privileged setter | `P: H2.transferOwnership(address)`, var: `H2.admin`, path: `[H2.transferOwnership(address)]` | `transferOwnership(address)` is public/external, lacks access control modifiers, and writes privileged state variable `admin`. |
| `h3.sol` | Unchecked send | `U: H3.refund()`, path: `[H3.refund()]` | `refund()` performs `payable(msg.sender).send(a)` without verifying the boolean return value. |
| `h4.sol` | Inline guard negative control | None | `setOwner(address)` has inline check `require(msg.sender == owner, 'no');` protecting the write to `owner`. |
