# Encrypted blob spec (draft)

Only non-obvious quirks live here for now. See `src/messages.ts` for the current layout.

## `asset_id` lookup chain

Spending needs the `asset_id` preimage, which lives in `Warptoad.assetSources`. That mapping is only filled on
chains where a factory deployed the wrapper, not on every chain where notes of the asset exist.
This would mean the client would need to search every chain for this asset_id.

So instead the blob carries the giga index of a chain where `assetSources[asset_id]` is filled. The sender always knows one:
wherever they resolved the `asset_id` themselves.

crosschain constrained encrypted blobs might also need this parameter, to constrain things like that. Just add it to
the signed data along side the rest of the order.
