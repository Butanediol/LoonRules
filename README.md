# LoonRules

Converts [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) domain rules and [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip) IP CIDR rules to [Loon](https://nsloon.app/) rule format.

When a name exists in both sources (e.g. `google`, `cn`), the domain rules and IP rules are merged into a single `.list` file.

Rules are rebuilt daily and published to GitHub Pages.

## Rule type mapping

| Source | Loon |
|--------|------|
| v2fly `domain:` | `DOMAIN-SUFFIX` |
| v2fly `full:` | `DOMAIN` |
| v2fly `keyword:` | `DOMAIN-KEYWORD` |
| v2fly `regexp:` | `DOMAIN-REGEX` |
| geoip IPv4 CIDR | `IP-CIDR` (with `no-resolve`) |
| geoip IPv6 CIDR | `IP-CIDR6` (with `no-resolve`) |

## Usage

Browse all available rule lists at: https://butanediol.github.io/LoonRules

## Build locally

```bash
git clone https://github.com/v2fly/domain-list-community.git
git clone --depth 1 -b release https://github.com/Loyalsoldier/geoip.git
go run . --datapath ./domain-list-community/data --geoippath ./geoip/text --outputdir ./output
```
