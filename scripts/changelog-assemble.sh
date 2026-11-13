#!/bin/sh
# changelog-assemble.sh — fold changelog.d/ fragments into CHANGELOG.md, or
# check them.
#
# Usage: scripts/changelog-assemble.sh <vX.Y.Z[-pre]> <YYYY-MM-DD>
#        scripts/changelog-assemble.sh --check
#
# Run from the repository root.
#
# THE FORM. The changelog has one entry per feature row of docs/SPEC.md, not
# one per pull request. A change that callers can see edits
# changelog.d/<feature>.md, where <feature> is the row's Feature slug, and
# every pull request on that feature edits the same file. Each entry is one
# line under a Keep a Changelog subsection (### Added, Changed, Deprecated,
# Removed, Fixed or Security):
#
#   - **<feature>**: <outcome for a caller, at most two sentences>. ([#N](<issue URL>))
#
# The issue link is optional. A breaking change goes under ### Changed as
# `- **BREAKING** <feature>: ...` and links its migration note in
# docs/README.md#upgrading.
#
# --check enforces the form and changes nothing. It fails when a fragment's
# name is not a Feature slug of docs/SPEC.md, or when an entry in a fragment or
# under `## [Unreleased]` breaks the form: an unknown subsection, text outside
# an entry, a continuation line, an unknown feature, a fragment entry naming
# another feature, more than two sentences, no closing period, or a BREAKING
# entry outside ### Changed or without its migration link. Every failure is
# reported, not just the first.
#
# ASSEMBLY. The release step folds the queue into a version section and
# deletes each fragment it folds in. It is a committed step performed before
# tagging, because release.yml never edits CHANGELOG.md: it reads the
# committed file at the tag, refuses the tag when a fragment or an
# [Unreleased] entry was left out or the version has no section
# (scripts/release-check-tag.sh), and publishes that section verbatim as the
# release body (scripts/release-notes.sh). `make release` runs this script
# and commits the result with VERSION.
#
#   - The body of `## [Unreleased]` and every fragment, in file-name order,
#     are merged under their `### <Subsection>` headings, one heading per
#     distinct subsection in order of first appearance, into a new
#     `## [<version>] - <date>` section directly below an emptied
#     `## [Unreleased]`. Every folded fragment is deleted;
#     changelog.d/.gitkeep stays.
#   - Link reference definitions (`[label]: URL`) are the file's footer and
#     stay at its end. When the footer has `[Unreleased]: <repo>/compare/<tag>...HEAD`,
#     it moves to compare from the new version, and a `[<version>]` link to
#     the version's tag range is added.
#
# PRUNING at a release boundary, so the file does not accumulate:
#
#   - A final release (vX.Y.Z, no pre-release suffix) folds the sections of
#     its own pre-releases (vX.Y.Z-alpha, vX.Y.Z-rc.N) into its section and
#     removes them and their links. Within each subsection an entry repeated
#     verbatim is kept once, and the entries of one feature are placed
#     together, in order of first appearance. Nothing else is merged.
#   - A final release of a new major version (v1.0.0 included) collapses
#     each earlier major N's version sections into one `## [vN.x]` summary
#     that lists the features those sections named, with a `[vN.x]` link to
#     their tag range. The forge release notes keep every release's full
#     text, so pruning loses nothing.
#
# Assembly fails, changing nothing, when: the version section already exists
# and fragments are still waiting, or `## [Unreleased]` still holds an entry
# (either would be silently left out); there is no `## [Unreleased]` heading;
# a fragment, the Unreleased body or a folded pre-release section has text
# outside a `### ` subsection, or a fragment has a `#`/`##` heading; there is
# nothing at all to release; or a major collapse meets an entry that names no
# feature or a footer with no `[Unreleased]` compare link to take the
# repository URL from. When the version section already exists, no fragment
# is waiting and [Unreleased] is empty it is a no-op, so a section written by
# hand still releases.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

changelog=CHANGELOG.md
fragdir=changelog.d
spec=docs/SPEC.md

# check implements --check.
check() {
  [ -f "$changelog" ] || die "$changelog not found (run from the repository root)"
  [ -f "$spec" ] || die "$spec not found (run from the repository root)"

  # The Feature column of the table under `## Features`.
  features=$(awk '
    /^## / { inside = ($0 ~ /^## +Features[ \t]*$/); next }
    inside && /^\|/ {
      split($0, cell, "|")
      slug = cell[2]
      gsub(/^[ \t]+|[ \t]+$/, "", slug)
      if (slug == "Feature" || slug ~ /^:?-+:?$/ || slug == "") next
      print slug
    }
  ' "$spec")
  [ -n "$features" ] || die "$spec has no Feature rows under ## Features"

  # awk never sees a line of an empty file, so empty fragments are named apart.
  set --
  empty=
  if [ -d "$fragdir" ]; then
    for f in "$fragdir"/*.md; do
      [ -f "$f" ] || continue
      if [ -s "$f" ]; then set -- "$@" "$f"; else empty=$empty$f$NL; fi
    done
  fi

  FEATURES=$features EMPTY=$empty awk -v changelog="$changelog" -v spec="$spec" '
    function err(where, msg) { print "changelog-assemble: " where ": " msg > "/dev/stderr"; bad++ }
    # entry checks one entry line; want is the feature it must name ("" for any
    # SPEC feature).
    function entry(where, line, want,   rest, i, feat, text, t, n) {
      if (line ~ /^- \*\*BREAKING\*\* /) {
        rest = substr(line, 16)
        if (sub_ != "Changed") err(where, "a BREAKING entry belongs under ### Changed")
        if (index(line, "docs/README.md#upgrading") == 0) err(where, "a BREAKING entry links its migration note in docs/README.md#upgrading")
        i = index(rest, ": ")
        if (i == 0) { err(where, "a BREAKING entry has the form `- **BREAKING** <feature>: <outcome>.`: " line); return }
        feat = substr(rest, 1, i - 1)
        text = substr(rest, i + 2)
      } else if (line ~ /^- \*\*[^*]+\*\*: /) {
        rest = substr(line, 5)
        i = index(rest, "**: ")
        feat = substr(rest, 1, i - 1)
        text = substr(rest, i + 4)
      } else {
        err(where, "an entry has the form `- **<feature>**: <outcome>.`: " line)
        return
      }
      if (!(feat in known)) err(where, "\"" feat "\" is not a Feature of " spec)
      else if (want != "" && feat != want) err(where, "an entry in " want ".md names \"" feat "\"; a fragment holds its own feature only")
      sub(/ \(\[#[0-9]+\]\([^)]+\)\)$/, "", text)
      if (text !~ /[^ ]/) { err(where, "the entry states no outcome"); return }
      if (text !~ /\.$/) err(where, "the outcome ends with a period: " line)
      t = text
      n = gsub(/[.!?] +[A-Z]/, "", t)
      if (n > 1) err(where, "an entry is at most two sentences: " line)
    }
    # body checks one line of a fragment or of the Unreleased body.
    function body(where, line, want) {
      if (line ~ /^[ \t]*$/) return
      if (line ~ /^### /) {
        sub_ = substr(line, 5)
        sub(/[ \t]+$/, "", sub_)
        if (!(sub_ in kac)) err(where, "\"" line "\" is not a Keep a Changelog subsection (Added, Changed, Deprecated, Removed, Fixed, Security)")
        return
      }
      if (line ~ /^#/) { err(where, "a heading other than ### : " line); return }
      if (line ~ /^[ \t]/) { err(where, "an entry is one line; continuation: " line); return }
      if (sub_ == "") { err(where, "text outside a ### subsection: " line); return }
      entry(where, line, want)
      entries++
    }
    BEGIN {
      n = split(ENVIRON["FEATURES"], f, "\n")
      for (i = 1; i <= n; i++) known[f[i]] = 1
      split("Added Changed Deprecated Removed Fixed Security", k, " ")
      for (i in k) kac[k[i]] = 1
    }
    FILENAME == changelog {
      if ($0 ~ /^## +\[Unreleased\][ \t]*$/) { inside = 1; sub_ = ""; next }
      if (!inside) next
      if ($0 ~ /^##? /) { inside = 0; next }
      if ($0 ~ /^\[[^]]+\]: /) next
      body(changelog ":" FNR, $0, "")
      next
    }
    # start begins a fragment: its name must be a feature.
    function start(file) {
      finish()
      name = file
      sub(/^.*\//, "", name)
      sub(/\.md$/, "", name)
      if (!(name in known)) err(file, "\"" name "\" is not a Feature of " spec "; a fragment is changelog.d/<feature>.md")
      prev = file; entries = 0; sub_ = ""
    }
    function finish() {
      if (prev != "" && entries == 0) err(prev, "the fragment holds no entry")
      prev = ""
    }
    FNR == 1 { start(FILENAME) }
    { body(FILENAME ":" FNR, $0, (name in known) ? name : "") }
    END {
      finish()
      n = split(ENVIRON["EMPTY"], e, "\n")
      for (i = 1; i <= n; i++) if (e[i] != "") { start(e[i]); finish() }
      if (bad) exit 1
    }
  ' "$changelog" "$@" || die "the changelog queue breaks the entry form (see above)"
  echo "changelog-assemble: $# fragment(s) and [Unreleased] keep the entry form"
}

if [ "${1-}" = --check ]; then
  [ $# -eq 1 ] || die "usage: $0 --check"
  check
  exit 0
fi

[ $# -eq 2 ] || die "usage: $0 <vX.Y.Z[-pre]> <YYYY-MM-DD> | --check"
version=$1
date=$2
matches "$version" "$VERSION_RE" || die "'$version' is not vX.Y.Z[-pre]"
matches "$date" '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' || die "'$date' is not YYYY-MM-DD"
[ -f "$changelog" ] || die "$changelog not found (run from the repository root)"

set --
if [ -d "$fragdir" ]; then
  for f in "$fragdir"/*.md; do
    [ -f "$f" ] && set -- "$@" "$f"
  done
fi

if grep -Eq "$(version_anchor "$version")" "$changelog"; then
  [ $# -eq 0 ] || die "$changelog already has a section for $version but $# fragment(s) are still in $fragdir/ — they would be left out of the release: $*"
  # The same hazard from the other side: entries still under [Unreleased]
  # would be tagged OUTSIDE the release they were written for.
  pending=$(unreleased_pending "$changelog")
  [ -z "$pending" ] || die "$changelog already has a section for $version but [Unreleased] still holds entries — they would be left out of the release: $pending"
  echo "changelog-assemble: $changelog already has a section for $version, no fragment is waiting and [Unreleased] is empty; nothing to do"
  exit 0
fi

tmp=$(mktemp "${changelog}.XXXXXX")
pruned=$(mktemp "${changelog}.XXXXXX")
trap 'rm -f "$tmp" "$pruned"' EXIT

# Pass 1: fold [Unreleased] and the fragments into the new section.
awk -v version="$version" -v date="$date" -v changelog="$changelog" '
function fail(msg) { print "changelog-assemble: " msg > "/dev/stderr"; failed = 1; exit 1 }
# add appends one line of a block to the current subsection, holding blank
# lines back so a block contributes no leading or trailing blanks.
function add(line) {
  if (line ~ /^[ \t]*$/) { if (started) pending++; return }
  if (!(cur in body)) { order[++n] = cur; body[cur] = "" }
  if (!started && body[cur] != "") body[cur] = body[cur] "\n"   # one blank between blocks
  while (pending > 0) { body[cur] = body[cur] "\n"; pending-- }
  body[cur] = body[cur] line "\n"
  started = 1; entries++
}
function heading(line) { cur = line; started = 0; pending = 0 }
function stray(where, line) {
  if (line ~ /^[ \t]*$/) return 0
  fail(where ": text outside a ### subsection: " line)
}
FILENAME == changelog {
  if (state == 0) {
    pre = pre $0 "\n"
    if ($0 ~ /^## +\[Unreleased\][ \t]*$/) { state = 1; cur = "" }
    next
  }
  if (state == 1) {
    if ($0 ~ /^## /) { state = 2 }
    else {
      if ($0 ~ /^# /) fail(changelog ": a # heading inside [Unreleased]: " $0)
      # With no released section yet, the footer follows [Unreleased]; it
      # stays the footer.
      if ($0 ~ /^\[[^]]+\]: /) { footer = footer $0 "\n"; next }
      if ($0 ~ /^### /) { heading($0); next }
      if (cur == "") { stray(changelog " [Unreleased]", $0); next }
      add($0); next
    }
  }
  if (version !~ /-/ && $0 ~ /^## /) {
    t = $0
    sub(/^## +\[?/, "", t)
    if (index(t, version "-") == 1) prerel++
  }
  rest = rest $0 "\n"; next
}
FNR == 1 { cur = ""; started = 0; pending = 0 }
{
  if ($0 ~ /^##? / || $0 ~ /^#[ \t]*$/) fail(FILENAME ": a fragment holds ### subsections only, not: " $0)
  if ($0 ~ /^### /) { heading($0); next }
  if (cur == "") { stray(FILENAME, $0); next }
  add($0)
}
END {
  if (failed) exit 1
  if (state == 0) { print "changelog-assemble: " changelog " has no ## [Unreleased] heading" > "/dev/stderr"; exit 1 }
  if (entries == 0 && prerel == 0) { print "changelog-assemble: nothing to release: [Unreleased] is empty and no fragment is waiting" > "/dev/stderr"; exit 1 }
  printf "%s\n## [%s] - %s\n", pre, version, date
  for (i = 1; i <= n; i++) printf "\n%s\n\n%s", order[i], body[order[i]]
  if (rest != "") printf "\n%s", rest
  if (footer != "") printf "\n%s", footer
}
' "$changelog" "$@" > "$tmp"

# Pass 2: prune at a release boundary and keep the footer links current. A
# file with no footer and nothing to prune passes through unchanged.
awk -v version="$version" '
function fail(msg) { print "changelog-assemble: " msg > "/dev/stderr"; failed = 1; exit 1 }
function blank(s) { return s ~ /^[ \t]*$/ }
function isref(s) { return s ~ /^\[[^]]+\]: / }
# verof is the version a ## heading names, or "".
function verof(s,   t, c) {
  t = s
  sub(/^## +\[?/, "", t)
  if (!match(t, /^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?/)) return ""
  c = substr(t, RLENGTH + 1, 1)
  if (c != "" && c != "]" && c != " ") return ""
  return substr(t, 1, RLENGTH)
}
function major(v,   p) { split(substr(v, 2), p, "."); return p[1] + 0 }
# featof is the feature an entry names, or "".
function featof(e) {
  if (match(e, /^- \*\*BREAKING\*\* [^:]+:/)) return substr(e, 16, RLENGTH - 16)
  if (match(e, /^- \*\*[^*]+\*\*/)) return substr(e, 5, RLENGTH - 6)
  return ""
}
function send(k) { return (k < ns) ? S[k + 1] - 1 : fs - 1 }
function emit(line) { O[++no] = line }
# collect adds the entries of section k to the merged subsections, dropping an
# entry already present verbatim in the same subsection.
function collect(k,   i, e, cur, blk, line) {
  e = send(k); cur = 0; blk = ""
  for (i = S[k] + 1; i <= e; i++) {
    line = L[i]
    if (line ~ /^### /) {
      keep(cur, blk); blk = ""
      if (!(line in subidx)) { subidx[line] = ++nsub; SN[nsub] = line; NB[nsub] = 0 }
      cur = subidx[line]
      continue
    }
    if (line ~ /^- /) {
      if (!cur) fail(L[S[k]] ": an entry outside a ### subsection: " line)
      keep(cur, blk); blk = line; continue
    }
    if (blank(line)) { if (blk != "") blk = blk "\n"; continue }
    if (blk == "") fail(L[S[k]] ": text outside an entry: " line)
    blk = blk "\n" line
  }
  keep(cur, blk)
}
function keep(cur, blk,   b) {
  sub(/\n+$/, "", blk)
  if (blk == "") return
  for (b = 1; b <= NB[cur]; b++) if (B[cur, b] == blk) return
  B[cur, ++NB[cur]] = blk
}
# merged emits the new section from the merged subsections, the entries of one
# feature together.
function merged(   j, b, c, f) {
  emit(L[S[me]]); emit("")
  for (j = 1; j <= nsub; j++) {
    if (NB[j] == 0) continue
    emit(SN[j]); emit("")
    for (b = 1; b <= NB[j]; b++) {
      if ((j, b) in done) continue
      emit(B[j, b]); done[j, b] = 1
      f = featof(B[j, b])
      if (f == "") continue
      for (c = b + 1; c <= NB[j]; c++)
        if (!((j, c) in done) && featof(B[j, c]) == f) { emit(B[j, c]); done[j, c] = 1 }
    }
    emit("")
  }
}
# summary emits the vM.x section that replaces major m'"'"'s sections.
function summary(m,   k, i, e, f, nf, list) {
  nf = 0
  for (k = 1; k <= ns; k++) {
    if (!(k in coll) || coll[k] != m) continue
    e = send(k)
    for (i = S[k] + 1; i <= e; i++) {
      if (L[i] !~ /^- /) continue
      f = featof(L[i])
      if (f == "") fail("cannot collapse the v" m " sections: an entry names no feature: " L[i])
      if (!((m, f) in seen)) { seen[m, f] = 1; list[++nf] = f }
    }
  }
  emit("## [v" m ".x]"); emit("")
  emit("Every v" m " release, by feature. Each tag'"'"'s release notes keep its full text."); emit("")
  for (i = 1; i <= nf; i++) emit("- **" list[i] "**")
  emit("")
}
# leftof is the tag a compare link starts from, or "".
function leftof(ref,   u, i) {
  i = index(ref, "/compare/")
  if (i == 0) return ""
  u = substr(ref, i + 9)
  i = index(u, "...")
  return (i == 0) ? "" : substr(u, 1, i - 1)
}
function refof(label,   r) { for (r = 1; r <= nr; r++) if (RL[r] == label) return R[r]; return "" }

{ L[++N] = $0 }
END {
  if (failed) exit 1
  final = (version !~ /-/)
  vmaj = major(version)

  # The footer: the trailing run of link references (and blank lines).
  fs = N + 1
  for (i = N; i >= 1; i--) {
    if (blank(L[i])) continue
    if (isref(L[i])) { fs = i; continue }
    break
  }
  nr = 0
  for (i = fs; i <= N; i++) {
    if (!isref(L[i])) continue
    R[++nr] = L[i]
    t = L[i]; sub(/^\[/, "", t); sub(/\]: .*$/, "", t)
    RL[nr] = t
  }

  ns = 0; me = 0
  for (i = 1; i < fs; i++) {
    if (L[i] !~ /^## /) continue
    S[++ns] = i; SV[ns] = verof(L[i])
    if (SV[ns] == version) me = ns
  }
  if (!me) fail("the assembled file has no section for " version)

  nfold = 0; ncoll = 0; oldestpre = ""
  if (final) {
    for (k = 1; k <= ns; k++) {
      if (index(SV[k], version "-") == 1) { fold[k] = 1; foldv[SV[k]] = 1; nfold++; oldestpre = SV[k]; continue }
      if (SV[k] == "" || k == me || major(SV[k]) >= vmaj) continue
      m = major(SV[k])
      coll[k] = m; collv[SV[k]] = m; ncoll++
      if (!(m in first)) { first[m] = k; newest[m] = SV[k]; majors[++nm] = m }
      oldest[m] = SV[k]
    }
  }

  # The repository URL and the previous tag, from [Unreleased]: <repo>/compare/<tag>...HEAD.
  ur = ""
  u = refof("Unreleased")
  if (u ~ /\/compare\/[^ ]+\.\.\.HEAD$/) {
    i = index(u, "/compare/")
    base = substr(u, 15, i - 15)
    prev = leftof(u)
    ur = u
  }
  if (ncoll > 0 && ur == "") fail("cannot link the collapsed major versions: the footer has no `[Unreleased]: <repo>/compare/<tag>...HEAD` link")

  if (nfold == 0 && ncoll == 0 && nr == 0) {
    for (i = 1; i <= N; i++) print L[i]
    exit 0
  }

  if (nfold > 0) { collect(me); for (k = 1; k <= ns; k++) if (k in fold) collect(k) }

  for (i = 1; i < (ns ? S[1] : fs); i++) emit(L[i])
  for (k = 1; k <= ns; k++) {
    if (k == me && nfold > 0) { merged(); continue }
    if (k in fold) continue
    if (k in coll) { if (first[coll[k]] == k) summary(coll[k]); continue }
    e = send(k)
    for (i = S[k]; i <= e; i++) emit(L[i])
  }
  while (no > 0 && blank(O[no])) no--

  # The footer, newest first: [Unreleased], the new version, then the rest
  # with folded versions dropped and collapsed ones replaced by their vM.x.
  nn = 0
  if (ur != "") {
    start = prev
    if (oldestpre != "" && leftof(refof(oldestpre)) != "") start = leftof(refof(oldestpre))
    F[++nn] = "[Unreleased]: " base "/compare/" version "...HEAD"
    F[++nn] = "[" version "]: " base "/compare/" start "..." version
  }
  for (r = 1; r <= nr; r++) {
    if (ur != "" && RL[r] == "Unreleased") continue
    if (RL[r] in foldv) continue
    if (RL[r] in collv) {
      m = collv[RL[r]]
      if (!(m in linked)) { linked[m] = 1; F[++nn] = summaryref(m) }
      continue
    }
    F[++nn] = R[r]
  }
  for (j = 1; j <= nm; j++) if (!(majors[j] in linked)) F[++nn] = summaryref(majors[j])

  for (i = 1; i <= no; i++) print O[i]
  if (nn > 0) { print ""; for (i = 1; i <= nn; i++) print F[i] }
}
function summaryref(m,   s) {
  s = leftof(refof(oldest[m]))
  if (s == "") s = oldest[m]
  return "[v" m ".x]: " base "/compare/" s "..." newest[m]
}
' "$tmp" > "$pruned"

cat "$pruned" > "$changelog"   # keeps the file's mode; mktemp creates 0600
rm -f "$tmp" "$pruned"
trap - EXIT
[ $# -eq 0 ] || rm -f "$@"
echo "changelog-assemble: folded $# fragment(s) into $changelog under [$version] - $date"
