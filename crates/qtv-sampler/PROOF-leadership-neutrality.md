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

## The one assumption

The proof is exact under the random oracle model of SHAKE256, that the outputs are independent uniform. It is a proof conditional on that model, not a proof of the hash, and that is the standard and unavoidable assumption, the same one the sortition's unpredictability rests on. Everything below is the deviation between that exact model and the finite implementation, and it is given as a bound, a quantity, not as the word negligible.

## The bounds, as quantities, checked at the extreme not the average

The finite implementation departs from the exact theorem in three ways, and because splitting manufactures many small accounts, each bound is stated at the extreme, a minimum stake account, which is where the error concentrates and where a splitter would live. The extreme is a two thousand QTOV account against the whole staked supply, whose worst case stake fraction f is two thousand over about four and a half million, which is about two to the minus eleven.

The discretisation of u. The output maps to a base 256 fraction of thirty two bytes, so u is uniform on a grid of two to the two hundred fifty six points, spacing two to the minus two hundred fifty six. An account leads when its u lands in a window of width f just below one, and that window holds f over the grid spacing points, so the discrete leadership probability equals the stake share to within one grid point. The absolute deviation is at most two to the minus two hundred fifty six. The relative deviation is two to the minus two hundred fifty six over f, which does grow as the stake shrinks, and at the extreme it is about two to the minus two hundred forty five. Small, and it is the smallest of the three.

The floating point rounding, and the cliff the floor guards. The score is minus the log of u over w in sixty four bit floating point, a relative rounding of about two to the minus fifty two, so which score is the minimum flips only when the top two are within that of each other, a leadership deviation of about two to the minus fifty two, and it does not depend on weight so long as one condition holds. The condition is the cliff. Near u equal to one the spacing of sixty four bit floats is about two to the minus fifty three, so any u within that of one rounds to exactly one and its score to zero, an automatic win. An account's winning window has width f. If f were below two to the minus fifty three the whole window would collapse onto the cliff and a dust account would auto win far above its share, an absolute error of order two to the minus fifty three that is exactly the concentration at small stake that was suspected. This is where the minimum self stake earns its place. At f about two to the minus eleven the winning window sits about two to the forty two above the cliff, roughly four trillion float steps wide, so it is finely resolved and the cliff never triggers. The floor is the load bearing element, and without it the neutrality proof would not hold at dust stake.

Ties. Two accounts land on the identical sixty four bit score with probability of order two to the minus fifty two, the float resolution, and the lowest score rule breaks the tie by first position, a bias of at most two to the minus fifty two.

The combined bound. At the extreme, a minimum stake account, the deviation of the leadership probability from the exact stake share is the sum of these, dominated by the float terms, about two to the minus fifty one, which is about four point four times ten to the minus sixteen. That is the epsilon. It is clean at the extreme, and it is clean because the two thousand QTOV floor holds every account about two to the forty two above the rounding cliff. The plain statement the founder asked for, the error does concentrate at small stake, and the minimum stake floor bounds it, and with the floor the combined deviation from exact neutrality is at most about four point four times ten to the minus sixteen for any account.

## What each test proves, and why both are kept

The two vectors prove different things and neither substitutes for the other.

The deterministic vector in leadership_proof.rs evaluates the theorem's own quantities, the minus log u over w scaling and the competing exponential integral, with no random draws. It proves the mathematics is internally consistent, that the model gives the stake share and that whole and split integrate to the identical value. It does not prove the implementation matches the theorem, because it computes the theorem's own formula rather than exercising the real sortition.

The statistical vector in leadership.rs runs the real construction over the real hash and confirms the measured leadership tracks the proven value. That is what tests that the implementation matches the theorem, the part the deterministic vector cannot reach. Its tolerance is now understood as sampling noise around a proven mean, not as the basis of the claim.

Both are kept. The claim is the theorem and its epsilon, the deterministic vector shows the mathematics is sound, and the sampled vector shows the code realises it.
