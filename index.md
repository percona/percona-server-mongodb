---
layout: default
title: Fork Status
---

{% assign data = site.data.branches.master %}

{% if data %}

<h2 class="branch-title">Branch: master</h2>
<p class="last-updated">Last Updated: {{ data.generated_at }} UTC</p>

{% include summary_grid.html data=data %}

{% if data.divergence.date_range.first %}

<p class="date-range">Date range: <strong>{{ data.divergence.date_range.first | slice: 0, 10 }} to {{ data.divergence.date_range.last | slice: 0, 10 }}</strong></p>
{% endif %}

<p class="upstream-link">Upstream: <a href="{{ data.upstream_url | replace: '.git', '' }}" target="_blank">{{ data.upstream_url | replace: '.git', '' | split: '/' | last }}</a> ({{ data.upstream_branch }})</p>

{% include filter_controls.html %}
{% include commits_table.html data=data %}

<script src="{{ '/assets/js/filter.js' | relative_url }}"></script>
<script src="{{ '/assets/js/pr-status.js' | relative_url }}"></script>
<script src="{{ '/assets/js/copy-sha.js' | relative_url }}"></script>
<script src="{{ '/assets/js/expand-details.js' | relative_url }}"></script>

{% else %}

<h2 class="branch-title">Branch: master</h2>
<p class="no-data-message">No branch data available. Add <code>_data/branches/master.json</code>.</p>

{% endif %}
