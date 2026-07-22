# The absolute finality threshold TAU

## What this is

Finality succeeds for a slot when the number of verified, published, selecting reveals whose attestations agree reaches an absolute count TAU. Membership stays by sortition and is unchanged. TAU is not a fraction of whoever published. It is a fixed count derived from the committee target and the honesty bound, so every node computes the same TAU from the registered set alone, whatever subset of the committee is heard from.

TAU lives in `finality_threshold` in `params.rs`. It is applied in `qtv-attest` by `aggregate` and by `Certificate::verify`, which admit a certificate only when the count of distinct entitled attesters reaches TAU. It is the same two thirds supermajority the fold certificate applies in `meets_quorum`, measured against the expected committee rather than against a folded stake total. The expected committee it is measured against is `expected_committee` in `sortition.rs`.

## The two inputs

The committee target is the budget bounded expected committee. `COMMITTEE_BUDGET` is the expected number of seats a slot draws once the validator set is at least the budget, and for a set smaller than the budget the expected committee is the whole eligible set. `expected_committee(weights, budget)` returns this expectation as an integer for the registered set, which is the same on every node because the registered set and the budget are consensus state.

The honesty bound is the safety hypothesis of the protocol recorded in `formal/QorusBFT.tla` as FaultBound, that fewer than one third of the stake is byzantine. It is held in `params.rs` as `ADVERSARY_STAKE_NUM` over `ADVERSARY_STAKE_DEN`, one third, so the honest stake is above two thirds.

## The derivation

The per slot committee size is random. Each eligible account is drawn independently with a stake weighted probability, so the number of seats is a binomial with mean the expected committee E. Because the size is random, TAU is set against the expected committee rather than against the seats that happen to appear, which is the Algorand class threshold.

TAU is the two thirds supermajority of the expected committee, the smallest count whose three times exceeds twice E, which is the floor of two thirds of E plus one. For E equal to four this is three, for E equal to twelve it is nine, for E equal to five hundred it is three hundred and thirty four. Two thirds is the threshold a byzantine fault tolerant agreement needs, not a bare majority, because a bare majority can be reached twice on two conflicting blocks at once.

## Safety

Consider two conflicting blocks that both finalise in one slot. Each has gathered at least TAU agreeing seats, so together they have gathered at least two times TAU seats out of the E that exist, and they therefore share at least two times TAU minus E seats. A seat shared between two conflicting blocks voted for both, and an honest seat votes for at most one block in a slot, so every shared seat is a byzantine seat. That forces the adversary to hold at least two times TAU minus E seats. With TAU the two thirds supermajority this shared count is above one third of E, above the honesty bound, so no adversary within the bound can hold it. Two conflicting blocks cannot both finalise. The adversary also cannot finalise a block on its own seats, since its at most one third of E is far below the two thirds threshold.

## Liveness

The adversary holds at most the floor of one third of E seats, so the honest set holds at least E minus that, which is at least the two thirds supermajority TAU. When the honest set is online it reaches TAU on its own and the slot finalises in a single aggregation with no extra round. A slot where enough honest seats are offline that the online seats fall short of TAU does not finalise and advances by view change. So a crash costs liveness for that slot and never lets a minority finalise, and the honest online path is the ordinary single aggregation, so sub-second finality is unchanged.

## The committee target is sufficient

The margin between the two thirds threshold and the one third adversary bound is a fixed fraction of E, so the per slot chance that a stake weighted binomial draw pushes the adversary seats up to the shared count TAU needs, or the honest seats below TAU, shrinks as the exponential of minus E times a fixed rate. At the current committee target of five hundred this per slot chance is negligible on each side, so the threshold is safe at the present committee target and needs no increase of the committee size.

## What it changes and does not change

Finality is measured against the expected committee and not against the observed publishers, and it is the same two thirds supermajority already used by the fold certificate, so the live path and the fold path agree. A crashed validator that publishes nothing lowers the margin toward TAU but cannot let a minority finalise. Sortition selection, the one time key uniqueness, the beacon, and the finality certificate are untouched, and finality stays the single aggregation it was, with no added round and no added message.
