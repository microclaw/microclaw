---
name: podcast
description: "Research a topic and produce a ready-to-listen podcast episode (a single audio file). Use when the user asks to make a podcast, generate an audio episode, a daily news digest in audio, a two-host show, or 'read this to me as a podcast'. Writes a spoken script then calls the generate_podcast tool to synthesize and stitch one mp3. Triggers on mentions of podcast, audio episode, news digest, narrate, two hosts, radio show, 播客, 做一期播客, 生成播客, 音频节目, 每日新闻播报, 双主播."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "Uses web_search/web_fetch (no API key) and the generate_podcast tool (requires media.podcast.enabled, media.tts credentials, and an ffmpeg binary). Works on macOS, Linux, and Windows."
---

# Generate a Podcast

Turn a topic (or a set of sources) into a single, listenable podcast episode and deliver
it to the user as an audio file. This mirrors a gather → curate → script → synthesize →
stitch pipeline.

## When to use

The user wants *audio*: "make a podcast about…", "give me today's AI news as an episode",
"做一期关于…的播客". The deliverable is one mp3 produced by the `generate_podcast` tool.

## Method

1. **Pick the angle and format.** Single host (monologue) or two hosts (dialogue)?
   How long (a 5-minute brief vs. a 15-minute deep dive)? Default to a tight ~5–8 minute
   single- or two-host episode unless told otherwise.
2. **Gather material** with `web_search` then `web_fetch` on the strongest sources. For a
   news digest, select the ~5 most important, distinct items — don't pad.
3. **Write a spoken script**, not an essay. Conversational sentences, no Markdown, no URLs
   read aloud, spell out things that don't speak well. Open with a short cold intro, then
   the segments, then a brief outro/sign-off.
4. **Break it into segments** for `generate_podcast` (see below). Each segment is one
   contiguous bit of speech with a single voice. For a two-host show, alternate voices.
   Keep each segment under ~4000 characters; split long passages into more segments.
5. **Synthesize** by calling `generate_podcast`. The tool TTS-es each segment and stitches
   them (with short silences) into one mp3, delivered to the user automatically. Then tell
   the user what you made (title, rough length).

## Calling generate_podcast

```json
{
  "title": "AI Weekly — Episode 12",
  "segments": [
    {"voice": "nova",   "text": "Welcome back to AI Weekly. I'm Nova."},
    {"voice": "onyx",   "text": "And I'm Onyx. This week: three stories worth your time."},
    {"voice": "nova",   "text": "First up..."},
    {"voice": "onyx",   "text": "That's all for today. Thanks for listening.", "pause_ms": 0}
  ]
}
```

- `voice` per segment (omit to use `media.podcast.default_voice`). Available voices:
  alloy, ash, ballad, coral, echo, fable, onyx, nova, sage, shimmer, verse. For two hosts,
  pick two distinct voices and alternate them consistently.
- `pause_ms` optionally overrides the silence after a segment (default from config).

## Recurring episodes

For "a podcast every morning", pair this with the `schedule` tool: schedule a task whose
prompt re-runs this skill (e.g. "make today's AI news digest podcast"). Each run produces
and delivers a fresh episode — the one-shot equivalent of a daily show.

## Quality bar

- Write for the ear: short sentences, natural transitions, signposting ("first… next…").
- Curate hard — a focused 5-item digest beats a rambling 12-item one.
- If a render fails with an ffmpeg or TTS error, relay it; the operator may need to install
  ffmpeg or enable `media.tts` / `media.podcast`.
