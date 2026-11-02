# Contributions

Libra is not accepting external source-code contributions at the moment. Pull requests will be closed without merging, regardless of their quality. This policy is about the project structure, not the change or the person who submitted it.

## Why not

The same source ships in two editions: this repository under the EUPL-1.2 and a proprietary Pro edition built on top of it. SenLab d.o.o. can do that because it holds the copyright on all of the code. An external contribution arrives under the EUPL alone, with the contributor retaining copyright on their lines. Because the EUPL is copyleft, the files that contribution touched could then no longer ship in the Pro edition. Merging one pull request could therefore break the two-edition model in the code it improved.

The usual solution is a contributor licence agreement that gives the project the right to license a contribution under both editions. Libra does not have one yet, and its wording remains a legal question. Until that is settled, accepting code would either break the model or use contributed work in ways the contributor never explicitly approved. For now, code contributions remain closed.

This policy does not put any restriction on what is already here. Everything in the FOSS edition stays there permanently, and a capability released here is never moved into Pro later. See [Editions](README.md#editions).

## What is welcome

Everything that is not a code change, and all of it is genuinely useful.

**Bugs.** Open a [bug report](../../issues/new?template=bug-report.yaml). Include what you sent, what you expected, what happened instead, the broker you run behind Libra, and the version from `libra --version`. A configuration, a policy and a request that reproduce the problem are worth more than a description of them. Leave out real keys, tokens and tenant data.

**Features.** Open a [feature request](../../issues/new?template=feature-request.yaml) describing the problem you need solved rather than the solution you have in mind.

**Documentation.** The [documentation](https://vela-tools.github.io/libra/docs/) is part of the product. If a guide is wrong, unclear, or silent on the case you hit, say so in an [issue](../../issues/new?template=help.yaml).

## Security

Never report a security vulnerability through a public issue. A policy that allows more than it says, a response that carries data a restriction should have removed, or a credential that reaches the broker is a security report, not a bug report. Follow the [Libra security policy](https://github.com/vela-tools/libra/security/policy), which takes reports privately through GitHub private vulnerability reporting and acknowledges them within two working days.
