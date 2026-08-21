# Diagram deck: design prompt

Working note. Paste everything below the rule into a fresh Claude session, and
attach `brand-fonts.css` from this directory.

Four attempts so far, each fixing the last one's problem and finding a new one.
v1 was a real flow diagram but its lane labels changed every page and its
content was thin. v2 was denser with a consistent frame but drifting toward
text. v3 fixed the facts and lost the diagram entirely, because the brief asked
for one frame on the left and another on the right, and a left/right split
turns a flow into two columns of prose. v4 is structurally right at last, and
unreadable in places: measuring its text boxes found thirteen severe
overprints across nine of twelve pages, and 97 percent of its type sitting in a
five point band, which is why it reads as flat and undigestible.

Everything below carries those lessons as hard numbers rather than as taste.

---

I need a 12 page **flow diagram** deck for a cloud security lab curriculum. One
page per lab. Each page is a single spatial diagram: boxes in meaningful
positions, connected by arrows, inside containers showing what lives where. A
student should be able to trace a path across the page with a finger.

**It is not a list, and not two columns of text.** If the page could be read
aloud top to bottom and lose nothing, it has failed.

## Output format

A single self contained HTML file designed to be printed to PDF from a browser.

- Page size **792 x 612 pt, US Letter landscape**. Set `@page { size: letter
  landscape; margin: 0 }` and size each page section to match exactly.
- Twelve page sections, each exactly one printed page, none spilling.
- **Real text and vector drawing, never raster.** The deck is merged into a
  searchable PDF, so text must survive extraction. No canvas, no base64 images,
  no screenshots. Use inline SVG containing genuine `<text>` elements, or
  positioned HTML with CSS borders. Arrows are SVG paths with `marker-end`.
- **Declare `<meta charset="utf-8">`.** Without it the middot in the running
  header and every arrow glyph render as mojibake and pull in a fallback font.
  This was verified, not guessed.
- Self contained: inline all CSS, embed nothing external, no CDN fonts.

## GRC Engineering Club branding

Match the written curriculum exactly. These are its real values, taken from the
stylesheet that renders the lab PDFs, and the deck is merged into the same
bound document, so anything else looks foreign on the facing page.

| Token | Value | Use |
|---|---|---|
| ink | `#0d0d0d` | node labels |
| body | `#232a33` | body text |
| muted | `#6d747e` | captions |
| accent | `#ED6F1B` | the one accent: arrows, hop numbers |
| accent dark | `#C25708` | secondary accent, used sparingly |
| panel | `#f7f4f0` | container fills, resting node backgrounds |
| line | `#ddd7d0` | borders, swimlane rules |

The accent is **orange**, `#ED6F1B`. In the source stylesheet its variable is
misleadingly named `--green`; ignore the name and use the value.

**Colour is not the hierarchy.** v4 used the accent only 24 times across the
whole deck against 421 uses of body ink, and that restraint was correct. Keep
it. Do not add colour to compensate for weak type hierarchy; fix the type.

**Typography: Inter for text, JetBrains Mono for anything a machine reads.**
File paths, commands, resource names, bucket names and ARNs are JetBrains Mono.
Prose, labels and captions are Inter. Same split the guides use.

Do not rely on these fonts being installed. An earlier draft silently fell back
to IBM Plex, which is why it looked like a different document. Use the attached
`brand-fonts.css`, about 138 KB, holding four faces subset and compressed to
WOFF2. Paste its contents into the `<style>` block. If you were not given that
file, ask for it rather than substituting a similar looking font.

The overall feel is the curriculum's: warm off white paper rather than pure
white, near black text, one orange accent, generous margins, thin warm rules.
Restrained and printed, not a dashboard.

## Type scale, which is where v4 actually failed

v4's problem was not only crowding. It used **seven type sizes with 97 percent
of all text inside a five point band**: 8.0, 9.3, 10.0, 10.7 and 12.0pt. A
reader cannot perceive 9.3 against 10.0 as a hierarchy; it reads as
inconsistency. With everything at one visual weight, nothing directs the eye,
so the whole page has to be read. That is what made it undigestible.

**Use exactly five sizes on the page, and only three inside the diagram:**

| Element | Size | Weight | Colour |
|---|---|---|---|
| lab number | 29pt | bold | accent |
| lab title | 20pt | bold | ink |
| node label | 12pt | semibold | ink |
| edge label | 10pt | regular | body |
| caption | 8pt | regular | muted |

Nothing between 8 and 10, and nothing between 10 and 12. The gaps are the
hierarchy. If something seems to need a size not on this list, it is a caption.

Running header, lane headers, and the PRODUCES / COST / TIME row use the 8pt
caption size, letterspaced, in muted.

## Density budget

v4 carried **119 words in 53 text objects inside the diagram body alone**, per
page. That is essay density inside a picture.

**Budget per page, diagram body only, excluding header, title, summary,
footnote and the PRODUCES row:**

- **60 words maximum**, about half of v4
- **30 text objects maximum**
- **6 nodes maximum**
- **4 hops maximum.** Five was too many. If a lab seems to need more, the extra
  ones are detail rather than structure, and belong in the footnote.

**Per element caps, which are limits and not targets:**

- node label: 3 words, 22 characters
- caption: 8 words, 55 characters, and it must fit **one line**
- edge label: 6 words, 40 characters, at most two lines

## Layout rules

**The page carries at most three text tiers**: a node's name, one caption under
it, and the label on an edge. There is no fourth tier, and in particular no
"read by" line under nodes. It was the third caption tier in an earlier draft
and it is reference material rather than anything read at a glance. Put who
reads a thing in the footnote if it matters, or leave it to the guide.

**Reserve boxes, do not merely position text.** Every node owns a fixed width
column. Its caption wraps inside that width or gets shortened; it may never
spill past the node's own column. No element may be placed in a box another
element already owns. Lay out the grid first, then fill it, and if the text
does not fit the box, cut the text.

**Edge labels sit in the lane gutters**, in fixed slots, aligned to the
vertical rules separating the lanes. Do not float them at arrow midpoints,
which puts them wherever the nodes happen to land. That is exactly how v4's
collisions happened: `queryable` and `asked` ended up at 100 percent overlap.

**Nothing may overlap anything.** If two elements would collide the page has
too much on it: remove a hop or shorten a caption. Never resolve a collision by
shrinking type, and never go below 8pt. Being at the floor is the signal to
cut, not to shrink.

## The structure

Every page carries the same two ideas, as **visual encodings, not regions of
the page**:

**THE HOPS.** The ordered path something takes, as **numbered arrows between
nodes**, 1 to 4, in the accent colour. The number sits on the edge, not in a
list. Each arrow carries a short label saying what travels along it, and where
useful what is refused: `403, refused by the bucket itself`.

**WHERE IT COMES TO REST.** The places a thing ends up and stays, as **nodes
inside the same diagram**, drawn as a filled panel plus a heavier border, using
the panel token for the fill. Not border alone: the containers already use
borders, and a reader must be able to tell a durable thing from a trust
boundary. Not a double rule, which is fussy at this size. The fill and border
are the whole distinction; they get the same single caption every other node
gets.

Wrap nodes in **boundary containers** showing ownership and trust: `your
machine`, `AWS account · us-east-1`, `GitHub`, `the GCP project`. The boundary
is often the actual lesson, because it shows where a credential stops being
yours and starts being the cloud's.

The **swimlane headers are decided, and identical on all twelve pages**:

> `DECLARE · ENFORCE · RECORD`

Do not substitute your own. This set is the curriculum's thesis in three words,
and it is the only one that survives every page: Lab 0.1 deploys nothing, Labs
3.3 and 3.4 are plan only with nothing in the cloud, and Lab 6.1 touches no
cloud at all. Headers naming provisioning or a request path break on four of
the twelve. Verbs do not.

It also stays orthogonal to the containers. The containers say **who holds a
thing**; the lanes say **what stage it is at**. Two channels carrying two
different facts. Do not let the lanes drift back into naming owners, or the
diagram spends a dimension repeating itself.

Above the diagram: lab number, title, cloud, and one or two plain sentences on
what the lab is really for. Below it: what it produces, what it costs, how long
it takes, then a single footnote line. Running header carries
`CGE-P LAB CURRICULUM · V2` and the lab number.

## Hard content rules

- **No em dashes anywhere.** The written curriculum uses zero across all fifteen
  documents. Use a comma, a colon, a middot, or a plain hyphen.
- **Every number must be correct.** Lab 2.3 creates **18 resources**, not 20.
  Two earlier drafts got this wrong. If unsure of a number, describe it
  qualitatively rather than guessing.
- Say what a control **does at request time**, not what document it maps to. A
  student should learn that a control refuses an action.

## The twelve pages

Each entry gives the lab, the cloud, what it produces, and the idea the page
should land.

1. **Lab 0.1 Prerequisites and Credentials** (AWS + GCP, free, 90 min).
   Produces a sandbox account, short lived credentials, the toolchain, and
   budget alarms. Nothing is deployed. You are establishing an identity in both
   clouds that expires on its own, and putting a ceiling on what everything
   after it can cost. Show the browser console session becoming a session
   reference in `~/.aws/config`, and that this reference is not a secret. Show
   that Terraform cannot read it directly and reaches it through a
   `credential_process` profile.

2. **Lab 2.2 Remote State Backend** (AWS, under $0.01 plus $1/mo per KMS key,
   20 min). Produces an S3 backend with native locking. The idea: without
   shared state, a fresh CI runner plans against nothing and proposes to create
   everything twice. State is what makes the pipeline in Chapter 4 possible.

3. **Lab 2.3 First Compliant Resource** (AWS, about $1/mo per KMS key, 60 to 75
   min). Produces **18 resources**: two buckets, a customer managed key, and
   their configuration. The idea: you describe the controls once as Terraform,
   and AWS then enforces them on every request that follows. A non TLS request
   is refused by the bucket itself, and an upload naming the wrong key is
   refused before an object exists. Controls: SC-8, SC-8(1), SC-12, SC-13,
   SC-28, SC-28(1), AC-3, AC-6, AU-3, AU-9, AU-11, CP-9, SI-7, CM-6, CM-8.

4. **Lab 2.4 Modules for Compliance** (GCP, about $0.06 per key version per
   month, 45 to 60 min). Produces a reusable module with CMEK and a consumer
   pattern. The idea: a module turns a set of decisions into a default that
   every consumer inherits, so the argument happens once.

5. **Lab 2.5 IaC as Compliance Evidence** (AWS, under $0.01, 45 min). Produces
   an Object Lock evidence vault and `capture-evidence.sh`. The idea: evidence
   you can delete is not evidence. Object Lock makes it immutable, which also
   means a captured secret becomes permanently undeletable, so what you put in
   matters.

6. **Lab 3.3 Writing Rego** (GCP, free, plan only). Produces a policy library
   with metadata and test fixtures. The idea: a policy no test constrains
   cannot fail, so the lab breaks each policy on purpose and requires the tests
   to notice.

7. **Lab 3.4 Conftest and Terraform** (AWS, free, plan only). Produces AWS
   policy variants and `policy-gate.sh`. The idea: the gate runs against a
   Terraform plan, so a violation is caught before anything is created rather
   than found afterward.

8. **Lab 4.3 GRC Evidence Pipeline** (AWS, free). Produces
   `.github/workflows/grc-gate.yml`. The idea: the checks a human ran by hand
   become the thing that must pass before a merge.

9. **Lab 4.4 Chain of Custody** (AWS, free). Produces Cosign signing wired into
   the vault. The idea: a signature answers who produced this artifact and
   whether it changed, and verification must constrain the signer rather than
   accepting any signature.

10. **Lab 5.2 AWS Security Services** (AWS, $1 to $8 if left running a month,
    75 min). Produces CloudTrail, Config, Security Hub, and an Athena review.
    The idea: collecting logs is AU-3 and AU-11. Actually reading them is AU-6,
    and that costs a query engine. Controls include AU-2, AU-6, AU-10, AU-12,
    SI-4, RA-5, CM-2.

11. **Lab 5.4 GCP Security Services** (GCP, pennies, 75 to 90 min). Produces
    Org Policy, Workload Identity Federation, and Data Access logs. The idea:
    an org policy stops the action at the API for everyone, including someone
    clicking in the console, which is stronger than a module standard.
    Federation means no long lived key exists to leak.

12. **Lab 6.1 Introduction to OSCAL** (no cloud, free, 60 to 75 min). Produces
    a validated component definition and profile. The idea: the control
    narrative becomes a machine readable artifact that a tool can validate,
    rather than a document a human rereads.



## Check your own work before you hand it over

Every number in this brief is mechanically checkable, and the deck will be
checked against them. Verify each page yourself first:

- Exactly 12 pages, each exactly 792 x 612 pt, none spilling to a second sheet.
- Exactly five type sizes on the page, three of them inside the diagram. No
  size between 8 and 10, or between 10 and 12.
- Diagram body within budget: 60 words, 30 text objects, 6 nodes, 4 hops.
- **Zero overlapping text.** Not "few", zero. Two elements whose boxes intersect
  is a defect, not a compromise.
- Every caption on one line, inside its node's column.
- No em dashes. Lab 2.3 says 18 resources.
- Inter and JetBrains Mono only, no fallback font anywhere.

If any page fails, fix that page rather than lowering the standard for all of
them.

The repository has `docs/diagrams/check-deck.py`, which measures a deck PDF
against every number above and prints a per page table. It is what the deck
will be judged by, so there is no benefit in guessing.

## What good looks like

A student glances at a page for fifteen seconds and can trace, with a finger,
where the work starts, what acts on it, and where the result comes to rest.
They read it again after finishing the lab and every box maps to something they
actually created. Nothing on the page is a claim the labs do not back up.

Two tests, both hard to pass by accident:

**Cover the prose** and the page should still teach the shape of the lab.

**Glance for two seconds** and your eye should land on the node labels first,
the hop numbers second, and the captions only if you choose to read them. If
everything arrives at once, the type scale is wrong, not the content.
