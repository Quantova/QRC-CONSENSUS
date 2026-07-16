# Proof of leadership neutrality under stake splitting

This is the proof that the leader rule is stake neutral under splitting, replacing the earlier statement that it was measured at a few split sizes. Committee membership is stake neutral because the selection threshold scales with stake, which is elementary. Leadership is the one soft spot the design names, because more accounts give more chances at a winning output, so the leader rule is proven neutral here rather than sampled and assumed.

## Statement

Under the exponential race leader rule, the probability that a bonded account leads a slot equals its share of the total native stake, exactly. Splitting a stake into several accounts does not raise the combined leadership probability. More strongly, the contribution a stake makes to the leader race, held as one account or split into any number of accounts summing to it, is identical in distribution, so splitting is not merely neutral in expectation, it is invisible.

## The construction, what the code does

For a slot each committee member has a leader output, the SHAKE256 sortition output over the member's committed one time preimage, the beacon, and the slot, with no randomizer. The output is mapped to a value u in the open interval zero to one, the base 256 fraction of its thirty two bytes. The member's leader score is s equals minus the natural log of u divided by w, where w is the member's native stake weight. The member with the lowest score leads. This is `leader_score` in sortition.rs and the lowest score selection in committee.rs.

## The model

Model the sortition outputs as independent and uniform on the open interval zero to one. This is the random oracle model of SHAKE256, and it is the same assumption the whole sortition already rests on for unpredictability. It is stated as an assumption about the hash, not proven here. Under it the u values are independent uniform across accounts.

## Lemma one, the score is exponential with rate w

If u is uniform on zero to one then X equals minus the natural log of u is exponential with rate one, because the probability that X exceeds t is the probability that u is below e to the minus t, which is e to the minus t for t at least zero. Then s equals X over w has probability of exceeding t equal to the probability that X exceeds w t, which is e to the minus w t. So s is exponential with rate w. A larger weight gives stochastically smaller scores and therefore a greater chance of being the minimum.

## Lemma two, competing exponentials

Let scores s one through s n be independent with s i exponential of rate w i. Then two facts hold.

First, the minimum of the scores is exponential with rate the sum of the w i, because the probability the minimum exceeds t is the product over i of the probability each s i exceeds t, which is the product of e to the minus w i t, equal to e to the minus the sum of w i times t.

Second, the probability that account i is the minimum is w i divided by the sum of the w j. This is the integral over t from zero to infinity of w i e to the minus w i t times the product over the other j of e to the minus w j t, which is w i times the integral of e to the minus the total weight times t, which is w i divided by the total weight.

## Theorem, leadership equals stake share and splitting is neutral

By lemma one each account's score is exponential with rate its weight. By the second fact of lemma two the probability account i leads is w i divided by the total weight, which is exactly its stake share.

Now split an account of weight W into accounts of weights w one through w k summing to W, leaving all other accounts unchanged. By the second fact of lemma two the probability that any one of the split accounts leads is the sum of their weights over the total, which is W over the total, exactly the probability the single account of weight W had. So splitting does not change the combined leadership probability.

The stronger form uses the first fact of lemma two. The minimum score among the split group is exponential with rate the sum of their weights, which is W, the identical distribution to the single account's exponential of rate W. So the group's contribution to the leader race is the same random variable in distribution as the single account's. Splitting is invisible, not just neutral in the mean.

## Why the naive rule fails, for contrast

If leadership were the lowest raw output with no weighting, each split account is an independent draw of a uniform, and the minimum of k uniforms is stochastically smaller than one uniform, so k small accounts beat one account of the same total stake. That is the soft spot. The division by w closes it exactly, because k accounts of weight W over k each contribute an exponential of rate W over k, and the minimum of k of those is exponential of rate W, back to the single account. The scaling cancels the extra draws exactly, which is why the cancellation is a proof and not a coincidence measured at one split size.

## The honest caveats, what the proof does and does not cover

The proof is exact under the random oracle model of SHAKE256, that the outputs are independent uniform. It is a proof conditional on that model, not a proof of the hash, and that is the standard and unavoidable assumption, the same one the sortition's unpredictability rests on.

The implementation maps thirty two bytes to a base 256 fraction, so u is uniform on a grid of two to the two hundred and fifty six points rather than the continuum, a discretisation error of order two to the minus two hundred and fifty six, negligible.

The score is computed in sixty four bit floating point, so minus the log of u over w carries a relative rounding of order two to the minus fifty two, far below any stake ratio that matters and not enough to bias which score is the minimum.

Two accounts with an identical score have probability of order two to the minus two hundred and fifty six, and the lowest score selection breaks such a tie by first position, which does not bias neutrality materially.

None of these is a statistical tolerance. The theorem is exact. These are the negligible gaps between the exact model and the finite implementation, named rather than hidden.

## What the tests check

The deterministic conformance test evaluates the theorem's own quantities, not a sample. It confirms the score is exactly the minus log u over w scaling the theorem requires, so a group of weights summing to W has the competing exponential leadership probability W over the total computed from the closed form, and the whole and the split give the identical value with no tolerance. That is the proof made executable without a single random draw.

The statistical vector in leadership.rs remains, but it is now a confirmation that the real construction over the real hash tracks the proven value, not the basis of the claim. The claim is this theorem.
