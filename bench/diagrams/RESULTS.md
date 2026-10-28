# Diagram stress test: results

**36 generated network diagrams in 9 styles**, from clean vendor-style drawings to whiteboard photos and crooked scans, with an exact answer key: every device's position, label and type, every capture point's kind and mirror direction (in varied wording, on the mirror line or in the label), and every tool's port speed. Recorded 2026-10-28; total cost US$2.96.

SAM 3.1 boxes are matched to the answer key by overlap (IoU 0.5 or more); Muse Spark's reading is checked for every device SAM found. "Ready to pin" means every capture point (kind and direction), the packet broker and every tool were found and read correctly: what VisiLoop needs to pin findings on the diagram.

## Baseline (2 SAM prompts: rounded rectangle box, ellipse)

| Measure | Result |
|---|---|
| SAM 3.1 devices found | 526/536 (98%) |
| SAM extra boxes (not a device) | 0 |
| Muse Spark labels read correctly (of found) | 526/526 (100%) |
| Muse Spark device types correct (of found) | 525/526 (100%) |
| Capture points: kind correct | 67/71 (94%) |
| Capture points: mirror direction correct | 67/71 (94%) |
| Tool port speeds correct | 112/114 (98%) |
| **Diagrams ready to pin findings on** | **33/36 (92%)** |

| Style | SAM found | Labels | Types | Direction | Ready to pin |
|---|---|---|---|---|---|
| clean_tb (rounded boxes, top to bottom) | 53/53 (100%) | 53/53 (100%) | 53/53 (100%) | 8/8 (100%) | 4/4 (100%) |
| clean_lr (rounded boxes, left to right) | 63/63 (100%) | 63/63 (100%) | 62/63 (98%) | 7/7 (100%) | 4/4 (100%) |
| visio_mono (sharp black-and-white rectangles) | 50/50 (100%) | 50/50 (100%) | 50/50 (100%) | 7/7 (100%) | 4/4 (100%) |
| shapes_mixed (hexagons, cylinders, octagons, trapezoids) | 52/62 (84%) | 52/52 (100%) | 52/52 (100%) | 6/10 (60%) | 1/4 (25%) |
| organic (force-directed layout) | 59/59 (100%) | 59/59 (100%) | 59/59 (100%) | 9/9 (100%) | 4/4 (100%) |
| dark (dark background) | 60/60 (100%) | 60/60 (100%) | 60/60 (100%) | 7/7 (100%) | 4/4 (100%) |
| dense (16-23 devices, small text) | 88/88 (100%) | 88/88 (100%) | 88/88 (100%) | 10/10 (100%) | 4/4 (100%) |
| whiteboard (handwriting, photographed at an angle) | 53/53 (100%) | 53/53 (100%) | 53/53 (100%) | 7/7 (100%) | 4/4 (100%) |
| scan (grey printout scanned crooked) | 48/48 (100%) | 48/48 (100%) | 48/48 (100%) | 6/6 (100%) | 4/4 (100%) |

## Extended (9 SAM prompts: rounded rectangle box, ellipse, rectangle, hexagon, cylinder, octagon, trapezoid, parallelogram, circle)

| Measure | Result |
|---|---|
| SAM 3.1 devices found | 534/536 (100%) |
| SAM extra boxes (not a device) | 1 |
| Muse Spark labels read correctly (of found) | 534/534 (100%) |
| Muse Spark device types correct (of found) | 532/534 (100%) |
| Capture points: kind correct | 69/71 (97%) |
| Capture points: mirror direction correct | 69/71 (97%) |
| Tool port speeds correct | 114/114 (100%) |
| **Diagrams ready to pin findings on** | **34/36 (94%)** |

| Style | SAM found | Labels | Types | Direction | Ready to pin |
|---|---|---|---|---|---|
| clean_tb (rounded boxes, top to bottom) | 53/53 (100%) | 53/53 (100%) | 53/53 (100%) | 8/8 (100%) | 4/4 (100%) |
| clean_lr (rounded boxes, left to right) | 63/63 (100%) | 63/63 (100%) | 62/63 (98%) | 7/7 (100%) | 4/4 (100%) |
| visio_mono (sharp black-and-white rectangles) | 50/50 (100%) | 50/50 (100%) | 50/50 (100%) | 7/7 (100%) | 4/4 (100%) |
| shapes_mixed (hexagons, cylinders, octagons, trapezoids) | 60/62 (97%) | 60/60 (100%) | 60/60 (100%) | 8/10 (80%) | 2/4 (50%) |
| organic (force-directed layout) | 59/59 (100%) | 59/59 (100%) | 59/59 (100%) | 9/9 (100%) | 4/4 (100%) |
| dark (dark background) | 60/60 (100%) | 60/60 (100%) | 60/60 (100%) | 7/7 (100%) | 4/4 (100%) |
| dense (16-23 devices, small text) | 88/88 (100%) | 88/88 (100%) | 87/88 (99%) | 10/10 (100%) | 4/4 (100%) |
| whiteboard (handwriting, photographed at an angle) | 53/53 (100%) | 53/53 (100%) | 53/53 (100%) | 7/7 (100%) | 4/4 (100%) |
| scan (grey printout scanned crooked) | 48/48 (100%) | 48/48 (100%) | 48/48 (100%) | 6/6 (100%) | 4/4 (100%) |

## Improved (3 SAM prompts: rounded rectangle box, ellipse, hexagon)

| Measure | Result |
|---|---|
| SAM 3.1 devices found | 534/536 (100%) |
| SAM extra boxes (not a device) | 0 |
| Muse Spark labels read correctly (of found) | 534/534 (100%) |
| Muse Spark device types correct (of found) | 532/534 (100%) |
| Capture points: kind correct | 69/71 (97%) |
| Capture points: mirror direction correct | 69/71 (97%) |
| Tool port speeds correct | 114/114 (100%) |
| SAM misses flagged by Muse Spark as untagged | 2/2 (100%) (0 false flags) |
| **Diagrams ready to pin findings on** | **34/36 (94%)** |

| Style | SAM found | Labels | Types | Direction | Ready to pin |
|---|---|---|---|---|---|
| clean_tb (rounded boxes, top to bottom) | 53/53 (100%) | 53/53 (100%) | 53/53 (100%) | 8/8 (100%) | 4/4 (100%) |
| clean_lr (rounded boxes, left to right) | 63/63 (100%) | 63/63 (100%) | 62/63 (98%) | 7/7 (100%) | 4/4 (100%) |
| visio_mono (sharp black-and-white rectangles) | 50/50 (100%) | 50/50 (100%) | 50/50 (100%) | 7/7 (100%) | 4/4 (100%) |
| shapes_mixed (hexagons, cylinders, octagons, trapezoids) | 60/62 (97%) | 60/60 (100%) | 60/60 (100%) | 8/10 (80%) | 2/4 (50%) |
| organic (force-directed layout) | 59/59 (100%) | 59/59 (100%) | 59/59 (100%) | 9/9 (100%) | 4/4 (100%) |
| dark (dark background) | 60/60 (100%) | 60/60 (100%) | 60/60 (100%) | 7/7 (100%) | 4/4 (100%) |
| dense (16-23 devices, small text) | 88/88 (100%) | 88/88 (100%) | 88/88 (100%) | 10/10 (100%) | 4/4 (100%) |
| whiteboard (handwriting, photographed at an angle) | 53/53 (100%) | 53/53 (100%) | 52/53 (98%) | 7/7 (100%) | 4/4 (100%) |
| scan (grey printout scanned crooked) | 48/48 (100%) | 48/48 (100%) | 48/48 (100%) | 6/6 (100%) | 4/4 (100%) |

## Capture points read wrongly or missed (improved)

| Diagram | Capture point | Truth | Written as | Where | Muse Spark read |
|---|---|---|---|---|---|
| d13_shapes_mixed | SPAN-2 | span rx_only | "mirror: inbound only" | edge | not found by SAM |
| d15_shapes_mixed | Mirror port (Distribution SW 2) | span tx_only | "TX only" | edge | not found by SAM |

Overlays of what SAM 3.1 found (green) and missed (red): `results/overlays/`.

## Reproduce

```
python bench/diagrams/make_diagrams.py   # 36 diagrams + answer key (needs Graphviz; images are committed)
python bench/diagrams/run_diagrams.py    # SAM 3.1 + Muse Spark (about US$2, resumable)
python bench/diagrams/score_diagrams.py  # this file
```
