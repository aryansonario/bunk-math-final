# BunkMath

A tool I built for PCCOER students to figure out one thing: if I bunk this class, how much does my attendance actually drop?


## Why I made this

Every college has that one moment where you're deciding whether to skip a lecture and you're doing weird mental math trying to figure out if you'll still be above the minimum attendance. I got tired of guessing, so I built something that just tells me directly.

## What it does

You log in with your college ID and password, and BunkMath connects to PCCOER's attendance system (EduPlus) and pulls your actual attendance — not manually entered, the real numbers. From there it builds your timetable automatically, and you can mark any upcoming class as a "planned bunk" to see exactly how it'll affect your attendance percentage before you actually skip it.

There's also a Ghost Bunk / Extra Credit mode to simulate further ahead — like how many classes you can miss for the rest of the semester and still stay safe.

## Features

- Pulls live attendance directly from college servers, no manual entry
- SVG progress rings for each subject's attendance
- What-if toggles on your timetable to simulate bunks before you actually do it
- Ghost Bunk / Extra Credit mode for planning ahead
- Today strip showing today's classes at a glance
- Batch-aware (H1/H2/H3)
- Export your data as CSV
- Works as a PWA — installable on phone

## Built with

HTML, CSS, JS (vanilla), deployed on Railway. Talks directly to PCCOER's EduPlus API.

## Scope right now

Only works for PCCOER since it's built around their specific attendance system. Would need backend changes to support other colleges.

## Still working on

Making sure credentials are handled safely on the client side — currently the main thing I'm improving.
