---
layout: default
title: Home
---

# Mal-Intel Pipeline

Malware intelligence research, static analysis, and detection engineering.

An automated, human-in-the-loop pipeline that ingests threat intelligence feeds, performs static analysis on malware samples, and generates analyst reports with YARA/Sigma detection rules — augmented by Claude AI at the synthesis layer.

**[View the project on GitHub](https://github.com/Winkz0/Mal-Intel-Pipeline)**

---

## Recent Analysis

{% for post in site.posts limit:10 %}
### [{{ post.title }}]({{ post.url | prepend: site.baseurl }})
<small>{{ post.date | date: "%B %d, %Y" }}</small>

{{ post.excerpt }}

---
{% endfor %}

{% if site.posts.size == 0 %}
*Analysis posts coming soon.*
{% endif %}
