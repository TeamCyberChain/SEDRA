# Saved operational dashboards

Open **Dashboards → New dashboard**, give the view a name and choose an executive starter, data protection starter or blank canvas. **Edit layout → Add widget** selects a recorded metric or a bounded operational breakdown. Edit titles/widths, move widgets earlier/later, remove them, then **Save dashboard**. Unsaved layout changes stay in the current browser page until saved or discarded. Select a saved view after reloading. **Archive** is recoverable from **Archived → Restore**.

Available widgets: metric card, daily activity, sensitive-pattern detections, destinations, classification snapshots, case review status, source coverage and recommended actions. Periods are 24 hours, 7 days or 30 days. The period belongs to the saved layout; case review and live identity priority remain current-state measures, explicitly labeled separately from period totals. Registered sources are the synthetic registered corpus, not discovered endpoint inventory. Counts of blocks do not establish breaches prevented, financial loss or detector efficacy.

Layouts are private to the authenticated Analyst account's stable principal. Administrator and permitted Analyst profiles can use aggregate dashboards; User profiles cannot read or create them. Existing MFA, session and CSRF checks apply. These UI endpoints do not accept integration API keys. No sharing, arbitrary SQL, custom JavaScript, iframe or external data source is supported.

`GET /api/dashboards` includes observed aggregates, the active owner's `saved_dashboards`, and metric/widget catalogs. `GET /api/dashboards/saved?archived=1` lists the owner's archived layouts. `POST /api/dashboards/saved` accepts exactly one closed action schema:

- `create`: action, name, description, days, widgets.
- `update`: the same layout fields plus id and expected_revision.
- `archive` or `restore`: action, id, expected_revision.

Dashboard IDs are server-generated 32-character hexadecimal strings. Widget IDs are unique 12-character hexadecimal strings per layout; fields are id, type, title, width (`half` or `full`) and, only for metric cards, metric. Labels are bounded plain text and escaped before rendering. Limits: 16 widgets, 20 active layouts and 100 total retained layouts per owner. Unknown fields/types/metrics and invalid periods are rejected. A SQLite immediate transaction serializes writes; stale revisions return HTTP 409. The browser retains the unsaved draft on a save conflict so an operator can discard and reload deliberately. Metadata-only dashboard actions are recorded in Audit Logs.

Layouts persist in `dashboards.sqlite` under the selected runtime data directory and survive activity resets/restarts. Back up this database with the other runtime stores. They contain configuration and titles, not copies of prompts, credentials or evidence packets. Reports remain a separate immutable snapshot/export feature. Layouts are not automatically shared across accounts, and widgets are not a general-purpose BI/data connector system.

Verification is recorded in `artifacts/test_summary.json` and `artifacts/dashboard_builder_v1.json`. Automated tests cover retention, ownership, User denial, CSRF, schema/size limits, soft archive/restore and concurrent stale writers. Browser checks use a separate loopback fixture with fictional accounts and synthetic records; they do not establish enterprise detection accuracy.
