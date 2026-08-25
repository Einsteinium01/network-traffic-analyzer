# Intelligent Network Traffic Analyzer
## Frontend Design Specification

Version: 1.0

---

# 1. Design Reference

The attached reference image is the PRIMARY visual inspiration for this application's frontend.

The frontend should closely follow the visual language of the reference:

- Dark enterprise dashboard
- Fixed left sidebar
- Rounded cards
- Dark charcoal surfaces
- Cyan primary accent
- Purple secondary accent
- Pink/magenta tertiary accent
- Subtle gradients
- Thin borders
- Compact typography
- High information density
- Large numerical metrics
- Right-side activity feed
- Large central visualization
- Small metric cards
- Minimal but polished animations

The goal is NOT to copy the content of the reference.

Instead, reproduce its:

- Layout philosophy
- Visual hierarchy
- Spacing
- Color language
- Card design
- Typography
- Navigation style
- Dashboard composition

The application should look like a professional modern network-security SaaS product.

It must NOT look like a generic college project.

---

# 2. Product Identity

Application name:

Network Intelligence

Full project name:

Intelligent Network Traffic Analyzer

Optional short brand:

NetIntel

The interface should use:

NetIntel

as the primary product branding.

Logo:

Use a simple geometric shield/network icon.

Do NOT create a complicated logo.

---

# 3. Overall Visual Style

Design category:

Modern Dark Enterprise SaaS Dashboard

Visual characteristics:

- Dark navy/black background
- Slightly lighter sidebar
- Rounded 16–20px cards
- Thin low-contrast borders
- Cyan primary accent
- Purple secondary accent
- Magenta tertiary accent
- Soft glow around selected/active elements
- Large readable metrics
- Small uppercase labels
- Minimal visual clutter

The design should feel similar to:

- Enterprise observability platforms
- Network operations dashboards
- Cybersecurity SaaS
- Infrastructure monitoring tools
- Modern developer platforms

---

# 4. Color Palette

Primary background:

#090D13

Sidebar background:

#070B12

Main surface:

#10141C

Card:

#121720

Elevated card:

#161B25

Border:

#202735

Border hover:

#303A4A

Primary text:

#F4F7FB

Secondary text:

#9AA4B2

Muted text:

#667085

---

## Accent Colors

Primary cyan:

#62E8F7

Secondary purple:

#A78BFA

Magenta:

#EC5BCB

Blue:

#60A5FA

---

## Security Status Colors

Normal:

#35D07F

Warning:

#F5B84B

Danger:

#FF5C6C

Critical:

#FF3B5C

These colors MUST ONLY be used when communicating security state.

---

# 5. Accent Gradient

Use a subtle cyan-to-purple gradient for selected primary controls.

Example:

Cyan:

#62E8F7

to

Purple:

#A78BFA

Use this sparingly.

Good uses:

- Active navigation
- Primary action
- Selected elements
- Small decorative glow

Do NOT use gradients on every card.

---

# 6. Typography

Primary font:

Inter

Fallback:

system-ui

Use a clean modern sans-serif.

Page title:

26–30px

Section title:

17–20px

Card label:

11–12px

Card value:

28–38px

Normal:

14px

Secondary:

12–13px

Uppercase labels should use:

font-weight: 500
letter-spacing: 0.08em

Example:

PACKETS CAPTURED

---

# 7. Application Layout

Desktop layout:

---------------------------------------------------------
| SIDEBAR | TOP SEARCH / HEADER                        |
|         |---------------------------------------------|
|         |                                             |
|         | DASHBOARD CONTENT                           |
|         |                                             |
|         |                                             |
---------------------------------------------------------

Sidebar:

248px

Main content:

Remaining viewport width

Page padding:

24px

Maximum content width:

none

The dashboard should use the available screen width efficiently.

---

# 8. Sidebar

The sidebar should closely resemble the reference image.

Width:

248px

Background:

#070B12

Right border:

1px solid #151B24

---

## Sidebar Header

Display:

[Network Icon]

NetIntel

Below:

NETWORK INTELLIGENCE

Use a small muted subtitle.

Example:

◈ NetIntel

NETWORK INTELLIGENCE

---

# 9. Sidebar Navigation

Navigation groups:

OVERVIEW

Dashboard

Live Traffic


SECURITY

Threats

Network Flows

Analytics


SYSTEM

Logs

Settings

---

## Navigation Item

Normal:

Transparent background

Muted icon

Secondary text

Hover:

Slightly lighter background

Active:

Dark cyan/purple gradient background

Thin cyan/purple right border

Example:

┌──────────────────────────┐
│ ▦  Dashboard             │
└──────────────────────────┘

Active item should have:

- Cyan icon
- White text
- Subtle gradient
- Soft glow
- Rounded 10px corners

---

# 10. Sidebar Bottom

Bottom navigation:

Support

System Status

Settings

Optional:

Version

v1.0.0

Keep these near the bottom.

---

# 11. Top Header

The top header should closely follow the reference.

Large rounded search bar:

┌─────────────────────────────────────────────┐
│ 🔍  SEARCH NETWORK...                       │
└─────────────────────────────────────────────┘

Right side:

Notification icon

System menu

User/avatar

---

# 12. Search

Placeholder:

SEARCH NETWORK...

Possible future searches:

- IP address
- Attack type
- Flow ID
- Threat
- Timestamp

For the first version, the search UI may be visual only.

Do not implement unnecessary global search functionality unless required.

---

# 13. Dashboard Header

Main content:

Network Overview

Subtitle:

Real-time visibility into network traffic and security events.

Right side:

[ START MONITORING ]

When active:

[ ● MONITORING ]

Primary button should use the cyan-purple gradient.

---

# 14. KPI Cards

The first row should contain FOUR large metric cards.

Layout:

4 equal cards.

---

## Card 1

Label:

TOTAL PACKETS

Value:

18,492

Supporting:

+12.4% vs previous interval

Icon:

Activity

---

## Card 2

Label:

TRAFFIC RATE

Value:

1.42 GB/s

Supporting:

Current throughput

Icon:

Network

---

## Card 3

Label:

THREATS DETECTED

Value:

27

Supporting:

+4 in last 5 min

Icon:

Shield Alert

---

## Card 4

Label:

SYSTEM HEALTH

Value:

Stable

Supporting:

Capture engine operational

Icon:

Shield Check

---

# 15. KPI Card Design

Each card:

Background:

#121720

Border:

1px solid #202735

Border radius:

16px

Padding:

22px

Subtle hover effect.

Do not make cards excessively colorful.

---

# 16. KPI Icon

Place the icon in the upper-right.

Icon container:

44px × 44px

Rounded:

12px

Each icon can have a subtle tinted background.

Example:

Traffic:

Cyan

Threat:

Magenta

Health:

Green

---

# 17. Large Central Dashboard Section

The center of the dashboard should be dominated by a large card.

Title:

Live Network Traffic

Subtitle:

Real-time packet distribution and flow activity.

Right side:

● LIVE LINK

---

# 18. Main Visualization

Instead of the world map shown in the reference, use a custom network visualization.

Preferred visualization:

Animated network topology.

Example:

                 [ INTERNET ]
                      |
              ┌───────┴───────┐
              │               │
           [Node]          [Node]
              \               /
               \             /
                [ LOCAL HOST ]
                    |
               [ ML ENGINE ]

The visualization should represent:

- Incoming traffic
- Outgoing traffic
- Active connections
- Threat events

Do not use a fake world map.

The visualization must represent actual project data where possible.

---

# 19. Network Visualization

Show:

Local machine

Active flows

External destinations

Threat nodes

Normal connections

Suspicious connections

Malicious connections

Color:

Normal:

Cyan/blue

Suspicious:

Amber

Malicious:

Red/magenta

---

# 20. Visualization Overlay

Inside the large visualization card, display a small overlay:

NETWORK LINK

Packets/sec

1,248

Latency

12 ms

Active Flows

84

Keep this visually similar to the "PRIMARY UPLINK" overlay in the reference.

---

# 21. Right-Side Security Feed

To the right of the large network visualization:

Security Events

This should resemble the reference image's Activity Feed.

Display events vertically.

Example:

SECURITY EVENTS

● Threat Detected

Port scan detected from
192.168.1.24

12 seconds ago


● Anomaly Detected

Unusual TCP connection
pattern identified.

2 minutes ago


● Monitoring Started

Live packet capture
initialized successfully.

5 minutes ago

---

# 22. Event Timeline

Use a vertical timeline.

Each event:

Icon

Event title

Description

Timestamp

Connector line

Example:

●
│
●
│
●

Use status colors for icons.

Do not use large icons.

---

# 23. Threat Event Colors

Normal event:

Cyan

Anomaly:

Purple

Warning:

Amber

Attack:

Red

Critical:

Magenta/red

---

# 24. Main Dashboard Bottom Metrics

Below the main visualization and event feed, display three compact metric cards.

---

## Card 1

PACKETS / SEC

1,248

Live capture rate

Circular progress indicator.

---

## Card 2

DETECTION RATE

96.8%

Model classification performance.

Circular progress indicator.

---

## Card 3

MODEL CONFIDENCE

94.2%

Average prediction confidence.

Circular progress indicator.

---

# 25. Circular Metrics

Use thin circular progress rings.

Do not use thick progress bars.

The ring should use:

Cyan

Purple

Magenta

depending on metric.

Center:

Value

Below:

Label

---

# 26. Live Traffic Page

Navigation:

Live Traffic

Layout:

Header

Filters

Traffic graph

Live table

---

# 27. Live Traffic Header

Title:

Live Network Traffic

Subtitle:

Monitor captured packets and network flows in real time.

Controls:

Interface selector

Protocol selector

Traffic type

Pause

---

# 28. Live Traffic Graph

Large chart:

Packets/sec

Secondary:

Bytes/sec

Time window:

60 seconds

Graph should update using Socket.IO.

Use subtle line glow.

Do not overanimate.

---

# 29. Live Traffic Table

Columns:

TIME

SOURCE

DESTINATION

PROTOCOL

PORT

SIZE

FLOW

PREDICTION

CONFIDENCE

Use compact rows.

IP addresses:

Monospace.

Prediction:

Small badge.

---

# 30. Threats Page

Title:

Threat Intelligence

Subtitle:

Detected network anomalies and security events.

Top:

Threat statistics.

Cards:

Critical

High

Medium

Low

Below:

Threat table.

---

# 31. Threat Table

Columns:

TIME

ATTACK

SOURCE

DESTINATION

SEVERITY

CONFIDENCE

STATUS

Example:

PORT SCAN

192.168.1.24

192.168.1.10

HIGH

98.2%

Detected

---

# 32. Threat Details Panel

Clicking a threat opens a right-side drawer.

Drawer width:

420–480px

Display:

Attack Type

Severity

Confidence

Source IP

Destination IP

Protocol

Ports

Duration

Packets

Bytes

Detection Time

ML Features

---

# 33. Network Flows Page

Title:

Network Flows

Display aggregated network flows.

Cards:

Active Flows

Normal

Suspicious

Malicious

Table:

FLOW ID

SOURCE

DESTINATION

PROTOCOL

DURATION

PACKETS

BYTES

PACKETS/SEC

PREDICTION

---

# 34. Analytics Page

Title:

Network Analytics

Charts:

Traffic Volume

Threat Activity

Attack Distribution

Protocol Distribution

Top Source IPs

Top Destination IPs

Use a 2-column grid.

Large charts:

2-column width

Small charts:

1-column width

---

# 35. Logs Page

Title:

Security Logs

Features:

Search

Filter

Sort

Export

Table:

TIMESTAMP

SOURCE

DESTINATION

EVENT

SEVERITY

CONFIDENCE

---

# 36. Settings Page

Sections:

Network Interface

Monitoring

Detection

Notifications

Model

System

Use grouped cards.

Example:

NETWORK INTERFACE

Interface:

[ Wi-Fi ▼ ]

Capture Mode:

[ Flow Based ]

---

# 37. Monitoring Status

The application must always communicate monitoring state.

States:

IDLE

STARTING

ACTIVE

STOPPING

ERROR

---

## IDLE

○ Monitoring inactive

---

## STARTING

◌ Initializing capture engine...

---

## ACTIVE

● Monitoring active

---

## STOPPING

◌ Stopping capture...

---

## ERROR

! Monitoring error

---

# 38. Global Status Indicator

The top navigation should always display:

● Monitoring Active

when monitoring is running.

The status indicator should subtly glow.

Do not constantly animate it.

---

# 39. Notifications

High-severity events should generate toast notifications.

Example:

┌───────────────────────────────┐
│ ⚠ HIGH SEVERITY               │
│ Port Scan Detected             │
│ 192.168.1.24                   │
│ 98.2% confidence               │
└───────────────────────────────┘

Duration:

5 seconds.

Allow dismissal.

Do not notify for normal traffic.

---

# 40. Empty States

Example:

No threats detected

Your monitoring system has not detected any security threats.

[ Start Monitoring ]

Use a subtle shield icon.

---

# 41. Loading States

Use skeleton loaders.

Do not use generic full-screen spinners.

Cards:

Skeleton

Charts:

Skeleton

Tables:

Skeleton rows

---

# 42. Error States

Example:

Unable to start monitoring

The packet capture engine could not access the selected network interface.

[ Retry ]

Never expose:

Python traceback

File paths

Internal exception details

---

# 43. Responsive Behavior

Desktop is the primary target.

At width < 1100px:

Collapse sidebar.

At width < 768px:

Sidebar becomes drawer.

Dashboard cards:

4 → 2 → 1

Main visualization:

2-column → 1-column

Tables:

Horizontal scroll.

---

# 44. Animation

Animations must be subtle and purposeful.

Allowed:

- Card hover
- Sidebar transition
- Active navigation
- Toast entrance
- Drawer entrance
- Chart updates
- Network connection movement

Duration:

150–350ms.

Avoid:

- Constant background animations
- Excessive glowing
- Bouncing elements
- Large page transitions
- Decorative animations

---

# 45. Glass / Glow Effects

Use very subtle effects.

Allowed:

Selected navigation glow

Primary button glow

Active monitoring indicator

Threat notification glow

Avoid turning the entire UI into glassmorphism.

Cards should remain mostly solid.

---

# 46. Border Radius

Primary cards:

16px

Large cards:

18–20px

Buttons:

10–12px

Small badges:

6–8px

Sidebar items:

10px

---

# 47. Icons

Use:

Lucide React

or

React Icons.

Do not use emoji icons.

Recommended:

Dashboard:

LayoutDashboard

Traffic:

Activity

Threats:

ShieldAlert

Flows:

GitBranch

Analytics:

ChartNoAxesCombined

Logs:

FileText

Settings:

Settings

Notifications:

Bell

---

# 48. Tables

Use dense professional tables.

Header:

Small uppercase text.

Rows:

48–56px

Hover:

Subtle background change.

Avoid excessive borders between every cell.

Use horizontal separators between rows.

---

# 49. IP Addresses

Use monospace.

Example:

192.168.1.24

Color:

Primary text

Do not color every IP address.

---

# 50. Threat Badges

Use compact pills.

NORMAL

SUSPICIOUS

ATTACK

CRITICAL

Example:

[ ATTACK ]

Red background with low opacity.

Text:

Red/white depending on contrast.

---

# 51. Accessibility

Maintain:

Keyboard navigation

Visible focus

ARIA labels

Semantic HTML

Readable contrast

Color + text for severity

Do not rely on color alone.

---

# 52. Performance

The application receives real-time network events.

Do not render every packet as an individual React update.

Use batching.

Recommended UI update interval:

250–500ms.

Keep a bounded live data buffer.

Maximum live table entries:

50–100.

Older entries should be discarded from the live view but preserved in backend logs.

---

# 53. Socket.IO

Use a centralized Socket.IO service.

Events:

monitoring_started

monitoring_stopped

packet_update

flow_update

statistics_update

threat_detected

system_error

Do NOT create independent socket connections in individual components.

---

# 54. React Architecture

Use:

components/

pages/

layouts/

services/

hooks/

context/

styles/

---

Components:

Layout

Sidebar

TopBar

MetricCard

TrafficChart

NetworkGraph

SecurityFeed

ThreatBadge

ThreatDrawer

LiveTrafficTable

CircularMetric

MonitoringButton

---

# 55. Design Tokens

Create CSS variables.

Example:

--bg-primary

--bg-sidebar

--bg-card

--border

--text-primary

--text-secondary

--cyan

--purple

--magenta

--success

--warning

--danger

Use these consistently.

Do not hardcode colors throughout components.

---

# 56. Do Not Introduce Unnecessary Libraries

Preferred:

React

Vite

React Router

Axios

Socket.IO Client

Chart.js / Recharts

Lucide React

Bootstrap OR Tailwind

Do not install multiple libraries that solve the same problem.

If a new library is required:

Explain why before installing it.

---

# 57. Frontend Functional Boundary

React is ONLY responsible for:

- Display
- User interaction
- Charts
- Tables
- Filters
- API requests
- WebSocket events

React must NOT:

- Capture raw packets
- Access Scapy
- Load ML models
- Access SQLite directly
- Perform packet inspection

Architecture:

React

↓

REST / Socket.IO

↓

Flask

↓

Services

↓

Packet Capture / Flow Engine / ML / Database

---

# 58. Important Data Rule

The UI should distinguish between:

Packets

Flows

Threats

Statistics

Do not mix these concepts.

Example:

Packets captured:

18,492

Active flows:

84

Threats:

27

---

# 59. Final Dashboard Composition

The primary dashboard should visually follow this structure:

┌────────────┬────────────────────────────────────────────┐
│            │ Search Network...              ● Active    │
│            ├────────────────────────────────────────────┤
│            │                                            │
│  NetIntel  │ Network Overview                           │
│            │ Real-time network intelligence              │
│ Dashboard  │                                            │
│ Live       │ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐       │
│ Traffic    │ │Packets│ │Rate  │ │Threat│ │Health│       │
│            │ └──────┘ └──────┘ └──────┘ └──────┘       │
│ Threats    │                                            │
│ Flows      │ ┌─────────────────────────┐ ┌──────────┐ │
│ Analytics  │ │                         │ │          │ │
│ Logs       │ │   LIVE NETWORK          │ │ SECURITY │ │
│ Settings   │ │   VISUALIZATION         │ │ EVENTS   │ │
│            │ │                         │ │          │ │
│            │ │                         │ │          │ │
│            │ └─────────────────────────┘ └──────────┘ │
│            │                                            │
│            │ ┌────────┐ ┌────────┐ ┌────────┐          │
│            │ │Packets │ │Detect  │ │Model   │          │
│            │ │/sec    │ │Rate    │ │Conf.   │          │
│            │ └────────┘ └────────┘ └────────┘          │
└────────────┴────────────────────────────────────────────┘

This composition should be the primary visual target.

---

# 60. Final Design Principle

The interface should make a user feel:

"I am looking at a professional network intelligence platform."

It should NOT make the user feel:

"This is a student dashboard with cybersecurity colors."

Use the attached reference image as the primary visual inspiration for:

- Layout
- Spacing
- Card proportions
- Sidebar
- Navigation
- Typography
- Color relationships
- Visual density
- Dashboard composition

Use actual project data wherever possible.

Never create fake metrics once the backend is available.