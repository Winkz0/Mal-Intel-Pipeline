---
layout: default
title: Home
---

# Mal-Intel Pipeline

Stay Vigilant.

I've always been interested in analyzing malware and seeing what it's capable of. There's always a thrill in my day job when I get a little piece of evil to break apart. While this tool isn't revolutionary, it's still something that I built and hopefully it can be used to teach others about the threat landscape. While the actual code was a major assist on Claude's part; I am the architect and the troubleshooter. This is a living project and will be built on continuously.

# What is it?
An automated, human-in-the-loop pipeline that ingests threat intelligence feeds, performs static analysis on malware samples, and generates analyst reports with YARA/Sigma detection rules — augmented by Claude AI at the synthesis layer.

**[View the project on GitHub](https://github.com/Winkz0/Mal-Intel-Pipeline)**

---

## Recent Analysis

{% for post in site.posts limit:10 %}
### [{{ post.title }}]({{ post.url | prepend: site.baseurl }})
<small>{{ post.date | date: "%B %d, %Y" }}</small>
{% if post.tags.size > 0 %}<small> · {% for tag in page.tags %}<code>{{ tag }}</code> {% endfor %}</small>{% endif %}

---
{% endfor %}

{% if site.posts.size == 0 %}
*Analysis posts coming soon.*
{% endif %}