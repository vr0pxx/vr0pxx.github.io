---
layout: page
icon: fas fa-bug
order: 2
title: CVE Research
---

<style>
.cve-header {
  text-align: center;
  padding: 2rem 1rem;
  margin-bottom: 2.5rem;
  background: linear-gradient(135deg, rgba(220, 38, 38, 0.1) 0%, rgba(239, 68, 68, 0.05) 100%);
  border-radius: 12px;
  border-left: 4px solid #dc2626;
}

.cve-header h1 {
  margin-bottom: 0.5rem;
  font-size: 1.8rem;
  color: var(--text-color);
}

.cve-header p {
  color: var(--text-muted-color);
  font-size: 1rem;
  margin: 0;
}

.cve-stats {
  display: flex;
  justify-content: center;
  gap: 2rem;
  margin-bottom: 3rem;
  flex-wrap: wrap;
}

.stat-box {
  text-align: center;
  padding: 1.5rem;
  background: var(--card-bg);
  border-radius: 10px;
  min-width: 120px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.08);
  border-top: 3px solid var(--stat-color);
}

.stat-number {
  font-size: 2.5rem;
  font-weight: bold;
  color: var(--stat-color);
  line-height: 1;
}

.stat-label {
  color: var(--text-muted-color);
  font-size: 0.85rem;
  text-transform: uppercase;
  margin-top: 0.5rem;
  letter-spacing: 1px;
}

.stat-box.critical { --stat-color: #9333ea; }
.stat-box.high { --stat-color: #ef4444; }
.stat-box.medium { --stat-color: #f59e0b; }
.stat-box.low { --stat-color: #10b981; }

.timeline-container {
  position: relative;
  margin: 3rem 0;
}

.timeline-year {
  margin-bottom: 3rem;
}

.year-header {
  position: relative;
  display: flex;
  align-items: center;
  margin-bottom: 2rem;
  padding-left: 4rem;
}

.year-marker {
  position: absolute;
  left: 0;
  width: 60px;
  height: 60px;
  background: linear-gradient(135deg, #dc2626, #ef4444);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.2rem;
  font-weight: bold;
  color: white;
  box-shadow: 0 4px 12px rgba(220, 38, 38, 0.4);
  z-index: 2;
}

.year-line {
  flex: 1;
  height: 3px;
  background: linear-gradient(90deg, #dc2626, rgba(220, 38, 38, 0.2));
  border-radius: 2px;
  margin-left: 1rem;
}

.timeline-items {
  position: relative;
  padding-left: 4rem;
  border-left: 3px solid rgba(220, 38, 38, 0.2);
  margin-left: 30px;
}

.timeline-item {
  position: relative;
  margin-bottom: 2rem;
  padding-left: 2rem;
}

.timeline-dot {
  position: absolute;
  left: -2rem;
  top: 1.5rem;
  width: 16px;
  height: 16px;
  background: var(--severity-color);
  border: 3px solid var(--card-bg);
  border-radius: 50%;
  box-shadow: 0 0 0 3px var(--severity-color-light);
  z-index: 1;
}

.timeline-item.critical {
  --severity-color: #9333ea;
  --severity-color-light: rgba(147, 51, 234, 0.2);
}

.timeline-item.high {
  --severity-color: #ef4444;
  --severity-color-light: rgba(239, 68, 68, 0.2);
}

.timeline-item.medium {
  --severity-color: #f59e0b;
  --severity-color-light: rgba(245, 158, 11, 0.2);
}

.timeline-item.low {
  --severity-color: #10b981;
  --severity-color-light: rgba(16, 185, 129, 0.2);
}

.timeline-content {
  padding: 1.5rem;
  background: var(--card-bg);
  border-radius: 10px;
  border-left: 4px solid var(--severity-color);
  box-shadow: 0 2px 6px rgba(0,0,0,0.05);
  transition: transform 0.2s, box-shadow 0.2s;
}

.timeline-content:hover {
  transform: translateX(3px);
  box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}

.timeline-date {
  display: inline-block;
  padding: 0.3rem 0.8rem;
  background: var(--severity-color);
  color: white;
  border-radius: 20px;
  font-size: 0.8rem;
  font-weight: bold;
  margin-bottom: 0.8rem;
}

.cve-top {
  display: flex;
  justify-content: space-between;
  align-items: start;
  margin-bottom: 0.8rem;
  gap: 1rem;
  flex-wrap: wrap;
}

.cve-title {
  flex: 1;
  min-width: 200px;
}

.cve-title h3 {
  margin: 0;
  font-size: 1.2rem;
}

.cve-title h3 a {
  color: var(--text-color);
  text-decoration: none;
}

.cve-title h3 a:hover {
  color: #dc2626;
}

.severity-badge {
  padding: 0.4rem 0.9rem;
  background: var(--severity-color);
  color: white;
  border-radius: 20px;
  font-size: 0.75rem;
  font-weight: bold;
  text-transform: uppercase;
  white-space: nowrap;
}

.cve-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 1.2rem;
  margin-bottom: 0.8rem;
  font-size: 0.9rem;
  color: var(--text-muted-color);
}

.cve-meta span {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
}

.cve-meta code {
  padding: 0.2rem 0.5rem;
  background: var(--code-bg);
  border-radius: 4px;
  font-size: 0.85rem;
}

.cve-excerpt {
  margin-bottom: 1rem;
  line-height: 1.6;
}

.cve-link {
  display: inline-block;
  padding: 0.5rem 1.2rem;
  background: #dc2626;
  color: white;
  border-radius: 6px;
  text-decoration: none;
  font-size: 0.9rem;
  transition: background 0.2s;
}

.cve-link:hover {
  background: #b91c1c;
  color: white;
}

.empty-state {
  text-align: center;
  padding: 3rem 2rem;
  background: var(--card-bg);
  border-radius: 12px;
  border: 2px dashed var(--border-color);
}

.empty-state i {
  font-size: 3rem;
  color: var(--text-muted-color);
  opacity: 0.5;
  margin-bottom: 1rem;
}

.empty-state p {
  color: var(--text-muted-color);
  font-size: 1.1rem;
  margin: 0;
}

@media (max-width: 768px) {
  .cve-stats { gap: 1rem; }
  .stat-box { min-width: 100px; padding: 1rem; }
  .stat-number { font-size: 2rem; }
  .year-header { padding-left: 3rem; }
  .year-marker { width: 50px; height: 50px; font-size: 1rem; }
  .timeline-items { padding-left: 2rem; margin-left: 25px; }
  .timeline-item { padding-left: 1.5rem; }
  .timeline-dot { left: -1.5rem; }
}
</style>

<div class="cve-header">
  <h1><i class="fas fa-shield-virus" style="color: #dc2626;"></i> CVE Research</h1>
  <p>Security vulnerabilities discovered and responsibly disclosed</p>
</div>

{% assign cve_posts = site.categories['CVE'] | sort: 'date' | reverse %}
{% assign critical = cve_posts | where_exp: "post", "post.severity == 'Critical'" %}
{% assign high = cve_posts | where_exp: "post", "post.severity == 'High'" %}
{% assign medium = cve_posts | where_exp: "post", "post.severity == 'Medium'" %}
{% assign low = cve_posts | where_exp: "post", "post.severity == 'Low'" %}

<div class="cve-stats">
  <div class="stat-box critical">
    <div class="stat-number">{{ critical.size }}</div>
    <div class="stat-label">Critical</div>
  </div>
  
  <div class="stat-box high">
    <div class="stat-number">{{ high.size }}</div>
    <div class="stat-label">High</div>
  </div>
  
  <div class="stat-box medium">
    <div class="stat-number">{{ medium.size }}</div>
    <div class="stat-label">Medium</div>
  </div>
  
  <div class="stat-box low">
    <div class="stat-number">{{ low.size }}</div>
    <div class="stat-label">Low</div>
  </div>
</div>

<h2 style="margin-bottom: 2rem;"><i class="fas fa-clock-rotate-left" style="color: #dc2626;"></i> Timeline</h2>

<div class="timeline-container">
  {% assign posts_by_year = cve_posts | group_by_exp: "post", "post.date | date: '%Y'" %}
  
  {% for year_group in posts_by_year %}
  <div class="timeline-year">
    <div class="year-header">
      <div class="year-marker">{{ year_group.name }}</div>
      <div class="year-line"></div>
    </div>
    
    <div class="timeline-items">
      {% for post in year_group.items %}
      <div class="timeline-item {{ post.severity | downcase }}">
        <div class="timeline-dot"></div>
        
        <div class="timeline-content">
          <div class="timeline-date">
            <i class="far fa-calendar"></i> {{ post.date | date: "%B %d" }}
          </div>
          
          <div class="cve-top">
            <div class="cve-title">
              <h3><a href="{{ post.url | relative_url }}">{{ post.title }}</a></h3>
            </div>
            {% if post.severity %}
            <span class="severity-badge">{{ post.severity }}</span>
            {% endif %}
          </div>
          
          <div class="cve-meta">
            {% if post.cve_id %}
            <span>
              <i class="fas fa-tag"></i>
              <code>{{ post.cve_id }}</code>
            </span>
            {% endif %}
            {% if post.cvss_score %}
            <span>
              <i class="fas fa-chart-line"></i>
              CVSS: <strong>{{ post.cvss_score }}</strong>
            </span>
            {% endif %}
          </div>
          
          <div class="cve-excerpt">
            {{ post.excerpt | strip_html | truncatewords: 30 }}
          </div>
          
          <a href="{{ post.url | relative_url }}" class="cve-link">
            <i class="fas fa-arrow-right"></i> Ver detalles
          </a>
        </div>
      </div>
      {% endfor %}
    </div>
  </div>
  {% endfor %}
  
  {% if cve_posts.size == 0 %}
  <div class="empty-state">
    <i class="fas fa-search"></i>
    <p>Aún no hay CVEs publicados. ¡Pronto habrá investigación!</p>
  </div>
  {% endif %}
</div>

---

