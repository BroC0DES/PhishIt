# Identity Correlation & Attribution

## Overview

This module identifies and correlates related email threats to detect
possible malicious campaigns. It uses shared indicators such as IP
addresses, domains, URLs, Reply-To addresses, and timestamps to find
relationships between emails.

## My Role

**Role 5 – Identity Correlation & Attribution Engineer**

My module is responsible for:

- Building an email relationship graph
- Detecting possible email campaigns
- Correlating emails using shared indicators
- Calculating correlation scores
- Providing correlation reasons and confidence levels
- Performing IP intelligence lookup
- Calculating campaign attribution support scores
- Visualizing campaigns using an interactive PyVis graph

## Input

The current input is an `email.csv` file containing:

- `email_id`
- `sender`
- `domain`
- `ip`
- `url`
- `reply_to`
- `timestamp`

## Technologies Used

- Python
- Pandas
- NetworkX
- PyVis
- IPinfo API

## Current Correlation Factors

Emails are correlated using:

- Same IP
- Same Domain
- Same Sender
- Same URL
- Same URL Domain
- Same Reply-To
- Sent within 24 hours

## Campaign Detection

Related emails are grouped into possible campaigns based on their
shared indicators.

Example:

**Campaign C001**
- E1
- E2
- E3
- Shared IP: `1.1.1.1`
- Shared Domain: `fakebank.com`
- Shared Reply-To: `help@fakebank.com`

## Attribution

The module generates an Attribution Support Score and confidence level
based on the available shared indicators.

The score represents supporting evidence that emails may belong to the
same campaign. It does not definitively identify an attacker.

## IP Intelligence

IP addresses are enriched using IPinfo to obtain:

- Country
- City
- Region
- ISP / Organization

## Visualization

PyVis generates an interactive HTML graph:

`campaign_graph.html`

The graph displays relationships between emails, senders, domains,
IPs, URLs, and Reply-To addresses.

## Current Status

- [x] Email data processing
- [x] NetworkX graph
- [x] Campaign clustering
- [x] Email correlation
- [x] Shared indicator detection
- [x] IP intelligence
- [x] Attribution scoring
- [x] Attribution confidence
- [x] Interactive PyVis visualization

## Future Integration

The module will later integrate with the other project modules:

- NLP / Fraud Content Detection
- Header & Protocol Forensics
- Origin Traceability & Geolocation
- Domain Intelligence

Their outputs can be used as additional evidence for correlation and
campaign attribution.