# Citation

This work targets the Kaggle competition:

> Manish Bhatt, Catherine Huang, Owen Vallis, Jess Chang, Sherin Mathews, Blake Gatto,
> Maria Cruz, Yao Yan, and Martyna Plomecka. *AI Agent Security — Multi-Step Tool Attacks.*
> https://kaggle.com/competitions/ai-agent-security-multi-step-tool-attacks, 2026. Kaggle.

```bibtex
@misc{ai-agent-security-multi-step-tool-attacks,
  author = {Manish Bhatt and Catherine Huang and Owen Vallis and Jess Chang and
            Sherin Mathews and Blake Gatto and Maria Cruz and Yao Yan and Martyna Plomecka},
  title  = {AI Agent Security -- Multi-Step Tool Attacks},
  year   = {2026},
  howpublished = {\url{https://kaggle.com/competitions/ai-agent-security-multi-step-tool-attacks}},
  note   = {Kaggle}
}
```

## Competition facts (from the overview, recorded 2026-08-30)

- **Submission format:** code competition via Notebooks. Submit is enabled after a commit when:
  GPU notebook **≤ 15 h** run-time, **Internet disabled**, freely/publicly available external data
  and pre-trained models allowed.
- **Prizes:** 1st $15,000 · 2nd $10,000 · 3rd $8,000 · 4th $7,000 · 5th $5,000 (top-5 all paid),
  **plus two optional Working Note Awards of $2,500 each** for the best written descriptions of
  participants' methods, findings, and lessons learned.
- **Close:** 2026-09-01.

## Responsible-disclosure note

This repository studies attacks against a **sandboxed benchmark with synthetic markers**
(`SECRET_MARKER`, `*.invalid`/`*.example` endpoints) for **defensive** research, per the
competition's stated purpose. The guardrail gap we exploit (`OptimalGuardrail` inspects the
`http.post` URL, not the `data` channel — "Bug 1") is documented in `docs/CLAIMS_LEDGER.md` and
will be disclosed to the organizers above; a fixed reference guardrail + input sanitizer is in
`defense/`.
