# A05: An agentic pipeline for vulnerability identification

**Group.** Read [the submission guide](SUBMISSION.md) first. Dates are on
the course schedule.

Your group builds a system that takes open-source applications and finds
vulnerabilities in them. It must back every claim with evidence that an
independent party can check. You build it on **AgentLab**
(<https://github.com/giovannivigna/agentlab>), with an agent that
coordinates at least one static-analysis tool and one dynamic-analysis
tool, each exposed through an MCP server you write.

The output is a set of **finding reports** in the format of
[`FINDING_REPORT.md`](FINDING_REPORT.md). Read it first: it defines what
counts as a finding, and how the grader checks it.

---

## 1. Input and output

**Input.** One JSON file per target in `input/items/`:

```json
{
  "id": "t-03",
  "repository": "https://github.com/example/parser",
  "commit": "<40 hex>",
  "language": "c",
  "build_hint": "autotools; a fuzzing harness is in fuzz/",
  "entry_points": ["the command-line parser", "the libparser API"]
}
```

Targets are real C and C++ projects (possibly some in other languages, as
announced), pinned at commits that contain vulnerabilities. Some targets
are pinned at a version where known vulnerabilities have been fixed: a
system that reports something everywhere will produce false positives there.

**Output.** For every target, `output/items/<id>/summary.json` and one
directory per finding, as defined in the finding-report format.

**Datasets.** The template includes a **development set** of targets, with
the known vulnerabilities listed, so you can measure your pipeline. The
**evaluation set** is hidden. Its targets and vulnerabilities are similar
in kind to the development set's.

## 2. Architecture requirements

- **A static-analysis MCP server** that wraps one or more real static
  analyzers (for example CodeQL, Semgrep, the Clang Static Analyzer, or
  Infer) and returns structured results: locations, rules, and data-flow
  paths. A tool that only asks a model to read code does not count as static
  analysis.
- **A dynamic-analysis MCP server** that builds the target (for example with
  sanitizers), runs it on chosen inputs, and runs bounded fuzzing campaigns
  with harnesses that exist or that the agent writes. It returns structured
  results: exit status, sanitizer reports, coverage, crashing inputs.
- **An agent** that reads the target, plans, uses static results to choose
  where to look, uses dynamic analysis to confirm or refute hypotheses,
  deduplicates crashes by root cause, and writes reports.
- **Independent validation.** Before a finding is classified as
  `reproducible` or above, a separate step rebuilds the target from a clean
  checkout and replays the trigger. The finding's automated replay (format
  §4) must pass in your own pipeline before you report it.
- The AgentLab boundary holds: the agent reaches the model only through the
  gateway, and the outside world (cloning, builds, execution) only through
  your MCP servers.

**Budget per target** in the graded run: 60 minutes of wall-clock time and
US$8 of model usage, enforced. Write `summary.json` even when you run out.

## 3. The report

`REPORT.md`, at most 8 pages:

1. **Architecture**: the MCP servers and their tools, the agent's strategy,
   and how static results steer dynamic analysis.
2. **Results on the development set**: what was found, what was missed and
   why, false positives, cost, and time.
3. **Ablation**: your pipeline without the static-analysis server (the agent
   chooses targets for dynamic analysis on its own), and without the agent
   (static warnings reported directly). Compare.
4. **Discussion**: where the agent helped, where it hurt, and the validation
   problems you met.

Also include `CONTRIBUTIONS.md` and `AI_USAGE.md`.

## 4. Repository layout

```text
submission.toml          assignment = "A05", members, mode
agent/  mcp-static/  mcp-dynamic/  ...   your AgentLab containers
compose.yaml
input/items/             the development set (given)
REPORT.md  CONTRIBUTIONS.md  AI_USAGE.md
.cs279/                  course tools (do not modify)
```

`make up && make run` processes `input/items/` into `output/items/`.

**The graded run.** The grader runs your `compose.yaml` as you wrote it, in
the AgentLab `MODE` named by `mode` in `submission.toml` (`agent`, or `kb`
for the knowledge base too), **one target at a time**: for each target it
starts your stack, runs `agent` over an `input/items/` that holds that target
alone, and stops the stack. `make run` on your machine does the same over all
of `input/items/`.

- **The model.** The gateway is the course's: your `gateway` service is
  replaced by a relay to it, and every service receives `AGENT_GATEWAY_KEY`,
  a key for the course model (`AGENT_MODEL=external`) limited to the
  target's budget. Past the budget or the time limit, the target ends there;
  what you wrote to `output/` by then is graded.
- **The network.** Your services keep the networks you gave them, so your
  MCP servers can reach the internet as they do on your machine.
- **Not allowed** in `compose.yaml` (a stack that uses any of these is not
  run): privileged containers; host networking or other host namespaces;
  devices; capabilities such as `SYS_ADMIN` or `NET_ADMIN` (`SYS_PTRACE` is
  fine); bind mounts, `env_file`s, build contexts, secrets or configs from
  outside the repository; external networks or volumes; the Docker socket.
- **Replays.** At most 10 findings per target are replayed, in the order of
  their directories (`finding-001` first): report your strongest first.

Feedback runs: **3 for the whole assignment**, on 2 development targets.

## 5. Grading

The grader runs your pipeline on the evaluation set, validates each
`report.json` against the schema, and replays every finding classified
`reproducible` or above three times.

A finding **matches** a known vulnerability if its location overlaps the
known one (same file, and the same function or a line range within 10
lines) and its root cause is the same, as checked by an AI judge. Let *K*
be the number of known vulnerabilities in the evaluation set.

- A matched finding that replays earns **1**. A matched finding that does not
  replay, or that is only a `candidate`, earns **0.5**. Each known
  vulnerability counts once, however many findings match it.
- Each finding classified `confirmed_vulnerability` that matches nothing
  known **and** does not replay costs **0.25**.
- A finding that matches nothing known but replays goes to the
  instructors. If it is a real vulnerability, it counts as a match (up to
  10 bonus points). If you think you have found a new vulnerability in a
  real project, tell the instructors before disclosing it anywhere.

| Criterion | Points | How |
|---|---:|---|
| Detection: 40 × max(0, credits − penalties) / *K* | 40 | automated + AI judge |
| Replay rate of findings claimed `reproducible` or above | 10 | automated |
| Report quality: completeness and correctness of the format's sections, on a sample of your findings | 15 | AI-assessed |
| Architecture: real static and dynamic tools behind MCP; static-guided dynamic analysis; independent validation | 15 | AI-assessed |
| `REPORT.md`: development results, ablations, discussion | 15 | AI-assessed |
| Engineering: runs as specified, schema-valid output, contributions | 5 | automated + AI-assessed |

The instructors confirm all AI root-cause judgments that change a match
before grades are released.
