# Free-tier Cloudflare zone hardening: TLS/security settings, security response
# headers, one rate-limit rule, optional custom WAF rules, DNSSEC, and the
# DNS-based controls (CAA pinning plus DMARC, SPF and null MX anti-spoofing).
# Everything here is available on the Cloudflare Free plan. The full managed WAF
# (OWASP) is Pro+ and intentionally NOT deployed here, the Free Managed Ruleset
# is applied automatically by Cloudflare on free zones.

locals {
  # ── Effective variable resolution ──
  # These three inputs default to null so a caller can say "unset" and inherit
  # whatever this module considers strong, rather than pinning a copy that goes
  # stale. A passthrough variable carrying its own default silently beats the
  # value here, and it does so in the weakening direction, which is how a
  # consumer once cut its own HSTS window in half on a module upgrade.
  # Resources below read local.eff_* and never var.* for these.
  eff_manage_zone_settings    = var.manage_zone_settings != null ? var.manage_zone_settings : true
  eff_manage_security_headers = var.manage_security_headers != null ? var.manage_security_headers : true
  eff_hsts_max_age            = var.hsts_max_age != null ? var.hsts_max_age : 63072000

  # Baseline TLS/security settings, all free tier. Override via var.zone_settings.
  default_zone_settings = {
    ssl                      = "strict" # Full (Strict)
    min_tls_version          = "1.2"
    tls_1_3                  = "on"
    always_use_https         = "on"
    automatic_https_rewrites = "on"
    opportunistic_encryption = "on"
    browser_check            = "on"
  }
  effective_zone_settings = local.eff_manage_zone_settings ? merge(local.default_zone_settings, var.zone_settings) : {}

  # Security response headers (name => value), assembled from fixed defaults +
  # conditional HSTS/CSP + caller extras.
  base_headers = merge(
    {
      "X-Content-Type-Options" = "nosniff"
      # DENY, not SAMEORIGIN. A hardening module should refuse framing outright;
      # a caller that genuinely frames its own pages can relax it through
      # extra_response_headers.
      "X-Frame-Options"    = "DENY"
      "Referrer-Policy"    = "strict-origin-when-cross-origin"
      "Permissions-Policy" = "geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()"
    },
    local.eff_hsts_max_age > 0 ? { "Strict-Transport-Security" = "max-age=${local.eff_hsts_max_age}; includeSubDomains; preload" } : {},
    var.content_security_policy != null ? { "Content-Security-Policy" = var.content_security_policy } : {},
    var.extra_response_headers,
  )
  # Omitted headers are dropped before the rule is built, leaving them to the
  # origin. See var.omit_response_headers for why that is sometimes required.
  managed_headers  = { for name, value in local.base_headers : name => value if !contains(var.omit_response_headers, name) }
  response_headers = { for name, value in local.managed_headers : name => { operation = "set", value = value } }
}

# ── Zone TLS / security settings ──────────────────────────────────────────
resource "cloudflare_zone_setting" "this" {
  for_each = local.effective_zone_settings

  zone_id    = var.zone_id
  setting_id = each.key
  value      = each.value
}

# ── Security response headers (Transform Rule) ────────────────────────────
resource "cloudflare_ruleset" "security_headers" {
  count = local.eff_manage_security_headers ? 1 : 0

  zone_id = var.zone_id
  name    = "${var.name_prefix}-security-headers"
  kind    = "zone"
  phase   = "http_response_headers_transform"

  rules = [{
    ref         = "security_headers"
    description = "Set baseline security response headers"
    expression  = "true"
    action      = "rewrite"
    action_parameters = {
      headers = local.response_headers
    }
  }]
}

# ── Rate limiting (free tier: one rule) ───────────────────────────────────
resource "cloudflare_ruleset" "rate_limit" {
  count = var.rate_limit != null ? 1 : 0

  zone_id = var.zone_id
  name    = "${var.name_prefix}-rate-limit"
  kind    = "zone"
  phase   = "http_ratelimit"

  rules = [{
    ref         = "rate_limit"
    description = "Rate limit abuse-prone path"
    expression  = var.rate_limit.expression
    action      = var.rate_limit.action
    ratelimit = {
      characteristics     = ["ip.src", "cf.colo.id"]
      period              = var.rate_limit.period
      requests_per_period = var.rate_limit.requests
      mitigation_timeout  = var.rate_limit.timeout
    }
  }]
}

# ── Custom WAF rules (free tier: up to 5) ─────────────────────────────────
resource "cloudflare_ruleset" "custom_firewall" {
  count = length(var.custom_firewall_rules) > 0 ? 1 : 0

  zone_id = var.zone_id
  name    = "${var.name_prefix}-custom-firewall"
  kind    = "zone"
  phase   = "http_request_firewall_custom"

  rules = [for r in var.custom_firewall_rules : {
    ref         = r.ref
    description = r.description
    expression  = r.expression
    action      = r.action
  }]
}

# ── Managed WAF (free tier) ───────────────────────────────────────────────
# Cloudflare gives every zone, including Free, a managed ruleset covering common
# exploit patterns. It is NOT deployed automatically: without an entrypoint
# ruleset in this phase, none of it runs, and the dashboard gives no warning. A
# zone can look thoroughly hardened (DNSSEC, HSTS, TLS 1.2+, rate limiting) while
# the actual attack-pattern rules are switched off.
#
# The id is resolved by NAME rather than pinned, because a literal 32-char id in
# config is opaque to a reader, and Cloudflare's own docs treat these ids as
# account-visible values rather than stable public constants.
data "cloudflare_rulesets" "managed" {
  count = var.manage_managed_waf ? 1 : 0

  zone_id = var.zone_id
}

locals {
  # `.rulesets`, not `.result`: both exist and carry the same shape, but every
  # attribute under `result` is marked deprecated in the v5 provider schema, so
  # it would warn now and break on a later major.
  managed_waf_id = try(one([
    for r in data.cloudflare_rulesets.managed[0].rulesets :
    r.id if r.kind == "managed" && r.phase == "http_request_firewall_managed"
  ]), null)
}

# Fail loudly rather than silently deploying nothing. A count that quietly
# resolves to 0 would leave the WAF off and the plan clean, which is the exact
# failure this resource exists to end.
check "managed_waf_available" {
  assert {
    condition     = !var.manage_managed_waf || local.managed_waf_id != null
    error_message = "manage_managed_waf is true but no managed ruleset was found in the http_request_firewall_managed phase for this zone. Check the token has Zone WAF Read."
  }
}

resource "cloudflare_ruleset" "managed_waf" {
  count = var.manage_managed_waf && local.managed_waf_id != null ? 1 : 0

  zone_id = var.zone_id
  name    = "${var.name_prefix}-managed-waf"
  kind    = "zone"
  phase   = "http_request_firewall_managed"

  rules = [{
    ref         = "execute_managed_free"
    description = "Execute the Cloudflare managed ruleset"
    expression  = "true"
    action      = "execute"
    enabled     = true

    action_parameters = {
      id = local.managed_waf_id
    }
  }]
}

# ── DNSSEC ────────────────────────────────────────────────────────────────
resource "cloudflare_zone_dnssec" "this" {
  count   = var.enable_dnssec ? 1 : 0
  zone_id = var.zone_id

  # Pinned, NOT left to default. In the v5 provider `status` is Optional but not
  # Computed, so omitting it makes the desired value null while the API reports
  # "active". That is a permanent diff: every plan showed this resource as
  # "will be updated in-place" with status going "active" -> null and all ten
  # computed attributes (ds, digest, key_tag, public_key, ...) becoming "known
  # after apply", on every zone, forever.
  #
  # Not cosmetic. The DS record is published at the registrar, so an apply that
  # actually pushed status away from active would break DNSSEC validation and
  # take the domain down for validating resolvers, with recovery gated on
  # registry DS TTLs. It also trained readers to skim past a real diff on a
  # DNS-critical resource, and buried genuine changes in permanent noise.
  status = "active"
}

# ── DNS-based hardening: CAA + email anti-spoofing ────────────────────────
# Free tier. These need var.zone_name as well as var.zone_id, because they are
# written at or under the apex.

check "dns_hardening_needs_zone_name" {
  assert {
    condition = (
      var.zone_name != null
      || (
        length(var.caa_issuers) == 0
        && var.dmarc_policy == null
        && var.apex_spf == null
        && !var.manage_null_mx
      )
    )
    error_message = "zone_name is required when caa_issuers, dmarc_policy, apex_spf or manage_null_mx is set: those records are written at or under the apex, and the zone id alone does not give the name."
  }
}

# CAA. issue covers the apex certificate, issuewild the wildcard that Universal
# SSL also provisions, so both are written for every allowed CA.
resource "cloudflare_dns_record" "caa_issue" {
  for_each = toset(var.caa_issuers)

  zone_id = var.zone_id
  name    = var.zone_name
  type    = "CAA"
  ttl     = 1
  comment = "${var.name_prefix}: restrict certificate issuance"
  data = {
    flags = 0
    tag   = "issue"
    value = each.value
  }
}

resource "cloudflare_dns_record" "caa_issuewild" {
  for_each = toset(var.caa_issuers)

  zone_id = var.zone_id
  name    = var.zone_name
  type    = "CAA"
  ttl     = 1
  comment = "${var.name_prefix}: restrict wildcard certificate issuance"
  data = {
    flags = 0
    tag   = "issuewild"
    value = each.value
  }
}

# DMARC. Without it, receivers cannot act on SPF/DKIM alignment, so the domain
# can be spoofed even when both are configured.
check "dmarc_fo_needs_ruf" {
  assert {
    condition     = var.dmarc_fo == null || var.dmarc_ruf != null
    error_message = "dmarc_fo controls when FORENSIC reports are generated, so it does nothing without dmarc_ruf. Either set dmarc_ruf or drop dmarc_fo, rather than leaving a tag that reads as configured but has no effect."
  }
}

resource "cloudflare_dns_record" "dmarc" {
  count = var.dmarc_policy != null ? 1 : 0

  zone_id = var.zone_id
  name    = "_dmarc.${var.zone_name}"
  type    = "TXT"
  ttl     = 1
  comment = "${var.name_prefix}: DMARC policy"
  # Tag order follows RFC 7489's own presentation: v and p first (v MUST be
  # first, and some parsers are strict about it), then policy modifiers, then
  # reporting. Every optional tag is OMITTED when null rather than written with
  # its default value, because a tag that is present pins behaviour, while an
  # absent one inherits whatever the RFC default becomes.
  # Wrapped in literal quotes. TXT content is a quoted character-string on the
  # wire, and Cloudflare adds the quotes when serving whether or not they are
  # stored, so this changes nothing about what resolvers see (verified by
  # comparing dig output before and after on a live record). It does clear the
  # advisory Cloudflare shows against every unquoted TXT record, which otherwise
  # sits permanently on DKIM, SPF and DMARC and trains people to ignore warnings
  # on exactly the records where a warning would matter.
  content = "\"${join("; ", concat(
    ["v=DMARC1", "p=${var.dmarc_policy}"],
    var.dmarc_sp != null ? ["sp=${var.dmarc_sp}"] : [],
    var.dmarc_adkim != null ? ["adkim=${var.dmarc_adkim}"] : [],
    var.dmarc_aspf != null ? ["aspf=${var.dmarc_aspf}"] : [],
    var.dmarc_pct != null ? ["pct=${var.dmarc_pct}"] : [],
    var.dmarc_rua != null ? ["rua=${var.dmarc_rua}"] : [],
    var.dmarc_ruf != null ? ["ruf=${var.dmarc_ruf}"] : [],
    var.dmarc_fo != null ? ["fo=${var.dmarc_fo}"] : [],
    var.dmarc_rf != null ? ["rf=${var.dmarc_rf}"] : [],
    var.dmarc_ri != null ? ["ri=${var.dmarc_ri}"] : [],
  ))}\""
}

# Apex SPF, for a domain declared as a non-sender.
resource "cloudflare_dns_record" "apex_spf" {
  count = var.apex_spf != null ? 1 : 0

  zone_id = var.zone_id
  name    = var.zone_name
  type    = "TXT"
  ttl     = 1
  comment = "${var.name_prefix}: apex SPF"
  # Quoted for the same reason as the DMARC record above. Callers pass the bare
  # policy (e.g. "v=spf1 -all"); the quoting is the module's job so no consumer
  # has to remember it.
  content = "\"${var.apex_spf}\""
}

# Null MX (RFC 7505): states that the domain accepts no mail.
resource "cloudflare_dns_record" "null_mx" {
  count = var.manage_null_mx ? 1 : 0

  zone_id  = var.zone_id
  name     = var.zone_name
  type     = "MX"
  ttl      = 1
  content  = "."
  priority = 0
  comment  = "${var.name_prefix}: null MX, domain sends and receives no mail"
}
