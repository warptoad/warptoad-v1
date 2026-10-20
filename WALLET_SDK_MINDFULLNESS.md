# TODO human review of this

# Wallet / SDK mindfulness

Privacy properties of warptoad that the circuit and contracts can **not** enforce on their own.
The protocol goal: a swaptoad lock, fill or cancel is indistinguishable from a normal shielded transfer.
Lock, fill, cancel and transfer share one circuit (`circuits/src/main.nr`) and one calldata shape
(`ShieldedTx` in `contracts/Warptoad.sol`): 4 nullifiers, 4 recipient commitments, 4 messages.
Everything that could still distinguish them, or link a user's transactions, is in the hands of the wallet SDK or the user.

## The protocol always leaks, unintended by design

Nothing known at the moment. Fake and real slots are indistinguishable on-chain, the public inputs that remain
(roots, edge indexes, timestamps, `public_hash`, `first_message_hash`) are all chosen by the SDK and covered below.

Things the protocol leaks **by design** (not listed further): shield and unshield amounts, assets and addresses,
and the relayer / sender address of every transaction.

## SDK needs to be mindful of this

### Roots come from a grid, not from "now"

The gap between the chosen `local_root` / `giga_root` and the block of inclusion reveals how long proving took,
which fingerprints hardware. Do not pick "the newest root at proving time".

- Pick the newest root as of a coarse boundary (for example the last root before a fixed block or time grid)
  so every wallet on the same grid picks the same root.
- `local_edge_index` / `giga_edge_index` follow from that root (`treeSize - 1`, checked by the contract).
- Local-only transactions must pass the real latest giga root on that same grid. Never the `0` sentinel root,
  that would mark the transaction as local-only.

### Timestamps come from the same grid

`proof_expire_time_stamp` and `historic_time_stamp` are prover chosen public inputs.

- Derive both from the grid value plus a **fixed window**, never from the wall clock at proving time.
- The window is identical for every transaction: transfer, lock, fill and cancel.
- A swaptoad fill asserts `proof_expire_time_stamp < expiry` of the signed order. Compute the expire stamp
  exactly as for a transfer and only fill if it is below `expiry`. Otherwise treat the order as expired.
  Never shorten the window to squeeze a fill in, a shorter window is a tell.
- The maker's `expiry` is never on-chain, its granularity does not matter.

### Maker's two fill messages

Slots 0 and 1 of a fill (`maker_change_commit`, `maker_new_commit`) are the maker's own notes.
The maker builds them at order time, possibly days before the fill, and the fill proves
`first_message_hash == keccak(messages[0], messages[1])` against the signed order.

- They must come from the same note-encryption path as ordinary notes: same tag scheme, same size.
- Slots 2 and 3 are the taker's own notes, built at fill time like any transfer.
- The cancel's three fake messages are ordinary fakes.

### Nonces are fresh randomness everywhere

- Fake spend slots and fake recipient slots each need a fresh random nonce. The fake nullifier
  `h(nonce, FAKE_NULLIFIER_DOMAIN)` and fake commitment `h(nonce, FAKE_COMMITMENT_DOMAIN)` are public.
  Reusing a real note's `shared_nonce` lets the sender of that note recompute them and link the transaction.
- Every real recipient commitment needs a fresh random `shared_nonce`. A predictable nonce lets anyone who knows
  the recipient's `owner_hash` enumerate their commitments.
- Two commitments with identical fields are identical leaves and publicly linkable.

### Fake messages

Fake messages must match real ones in size and tag shape (see `src/messages.ts`, random tag, never a zero tag).

### Orders are public once shared

An order carries the lock preimage, including the lock's `shared_nullifier_secret` (circuit component storage slot 2).
Anyone holding it can compute:

- the lock nullifier `h(shared_nullifier_secret, giga_leaf_index, local_leaf_index)`, so they see whether and when
  the lock is filled or cancelled, and on which chain
- both maker output hashes, since their `shared_nonce` is `hash_shared_nonce_swaptoad(shared_nullifier_secret, 0 | 1)`
  and the rest of the fields are in the order

Tracking stops at those outputs: spending them needs the owner's `nullifier_secret` (part of `owner_keys_hash`),
which is not in the order. Do not confuse the two secrets.

- `shared_nullifier_secret` must be fresh per lock.
- Takers need the order to check the lock's state before filling, so this leak is inherent.

### Locks need a real `owner_hash`

A fill asserts `locked_commitment.owner_hash == hash_owner(owner_keys_hash, current_giga_index)`.
An address-shaped `owner_hash` has no such preimage and can never be filled. Only cancel would work.

## User might mess this up

### Reusing `owner_keys_hash`

`owner_hash = h(owner_keys_hash, giga_index)` with `owner_keys_hash = h(pub_key.x, pub_key.y, nullifier_secret)`.
The maker hands `owner_keys_hash` to the taker as part of the lock preimage.

- Reusing it across chains or counterparties links every lock and commitment that shares it.
- A holder can brute-force the small `giga_index` to learn which chains the user is on.
- Fix: a fresh `nullifier_secret` per lock or per counterparty. The spending key (`pub_key`) can stay the same.

### Reusing `shared_nullifier_secret` and auth key across locks

One signed order then fills every lock that shares them. Each fill is at the agreed price, but the maker trades
more than they intended.

### Sharing an order with several takers

Every holder gets the tracking ability described under "Orders are public once shared", not just the one who fills.
Forcing one taker per lock would let a taker grief by never filling, costing the maker a cancel. Inherent trade-off.

### Non-issues

- A taker unshielding the outputs of a fill looks exactly like any other unshield.
