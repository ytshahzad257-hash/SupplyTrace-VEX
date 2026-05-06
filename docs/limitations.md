# Limitations

SupplyTrace-VEX is intentionally conservative. It is a research artifact for local evidence composition, not a production vulnerability management platform.

## Static Reachability Limits

Reachability analysis is static and source-based. It can miss dynamic imports, reflection, generated code, plugin loading, framework routing, dependency injection, monkey patching, and runtime configuration. A `reachable` status is contextual evidence, not proof of exploitability.

## Scanner Database Freshness

Scanner output depends on installed tools, local databases, network policy, scanner versions, and supported ecosystems. The same generated case may produce different scanner evidence across environments. SupplyTrace-VEX records tool availability and execution metadata so those differences remain visible.

## Synthetic Testbed Limitations

The generated testbed is controlled and intentionally small enough to support reproducible artifact review. It does not capture the full diversity of production dependency graphs, build systems, monorepos, private packages, compiled artifacts, or organization-specific deployment context.

## VEX-Style Status Is Not Vendor-Certified

Generated VEX-style records are local project-evidence summaries. They are not official vendor VEX attestations, legal claims, operational guarantees, or proof that a vulnerability cannot be exploited.

## Dynamic Language Limitations

Python and JavaScript allow dynamic import patterns, metaprogramming, conditional loading, and runtime dispatch. SupplyTrace-VEX marks uncertain cases as `unknown` or `under_investigation` where static analysis cannot resolve enough evidence.

## Container Scanning Limitations

Container-oriented cases model local image and layer context, but container results depend on local image availability, scanner support, base image metadata, and package database interpretation. Container package presence does not by itself prove application-level reachability.

## Evaluation Limitations

Evaluation metrics require normalized scanner-backed findings that can be mapped to local labels. If no such findings exist, metrics are reported as `not_available`. That status should not be interpreted as success, failure, or hidden improvement.
