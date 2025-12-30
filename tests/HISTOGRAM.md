# Toxic Frame Bug - Length Histograms

Detailed analysis of packet success rates by length for toxic byte patterns.

Generated: 2025-12-30T11:43:30.352846

**Test Parameters:** 10 iterations per length

## 0x4a (74 decimal) Patterns

### Classification Summary

- **SAFE**: 5 lengths

- **MAYBE**: 16 lengths

- **TOXIC**: 10 lengths


### Detailed Results

| Length | Success Rate | Success/Fail | Classification |
|--------|--------------|--------------|----------------|
| 100 | 100.0% | 100/  0 | SAFE     |
| 101 | 100.0% | 100/  0 | SAFE     |
| 102 | 99.0% |  99/  1 | MAYBE    |
| 103 | 100.0% | 100/  0 | SAFE     |
| 104 | 100.0% | 100/  0 | SAFE     |
| 105 | 100.0% | 100/  0 | SAFE     |
| 106 | 97.0% |  97/  3 | MAYBE    |
| 107 | 97.0% |  97/  3 | MAYBE    |
| 108 | 93.0% |  93/  7 | MAYBE    |
| 109 | 97.0% |  97/  3 | MAYBE    |
| 110 | 87.0% |  87/ 13 | MAYBE    |
| 111 | 74.0% |  74/ 26 | MAYBE    |
| 112 | 58.0% |  58/ 42 | MAYBE    |
| 113 | 58.0% |  58/ 42 | MAYBE    |
| 114 | 61.0% |  61/ 39 | MAYBE    |
| 115 | 40.0% |  40/ 60 | MAYBE    |
| 116 | 23.0% |  23/ 77 | MAYBE    |
| 117 | 25.0% |  25/ 75 | MAYBE    |
| 118 | 23.0% |  23/ 77 | MAYBE    |
| 119 |  8.0% |   8/ 92 | MAYBE    |
| 120 |  5.0% |   5/ 95 | MAYBE    |
| 121 |  0.0% |   0/100 | TOXIC    |
| 122 |  0.0% |   0/100 | TOXIC    |
| 123 |  0.0% |   0/100 | TOXIC    |
| 124 |  0.0% |   0/100 | TOXIC    |
| 125 |  0.0% |   0/100 | TOXIC    |
| 126 |  0.0% |   0/100 | TOXIC    |
| 127 |  0.0% |   0/100 | TOXIC    |
| 128 |  0.0% |   0/100 | TOXIC    |
| 129 |  0.0% |   0/100 | TOXIC    |
| 130 |  0.0% |   0/100 | TOXIC    |

**TOXIC LENGTHS:** 121-130 bytes (10 lengths)

**SAFE LENGTHS:** 100-105 bytes (5 lengths)

**INTERMITTENT LENGTHS:** 102-120 bytes (16 lengths)

**TRANSITION ZONE:** 105-121 bytes

### Transition Zone Details

| Length | Success Rate | Success/Fail | Classification |
|--------|--------------|--------------|----------------|
| 103 | 100.0% | 100/  0 | SAFE     |
| 104 | 100.0% | 100/  0 | SAFE     |
| 105 | 100.0% | 100/  0 | SAFE     |
| 106 | 97.0% |  97/  3 | MAYBE    |
| 107 | 97.0% |  97/  3 | MAYBE    |
| 108 | 93.0% |  93/  7 | MAYBE    |
| 109 | 97.0% |  97/  3 | MAYBE    |
| 110 | 87.0% |  87/ 13 | MAYBE    |
| 111 | 74.0% |  74/ 26 | MAYBE    |
| 112 | 58.0% |  58/ 42 | MAYBE    |
| 113 | 58.0% |  58/ 42 | MAYBE    |
| 114 | 61.0% |  61/ 39 | MAYBE    |
| 115 | 40.0% |  40/ 60 | MAYBE    |
| 116 | 23.0% |  23/ 77 | MAYBE    |
| 117 | 25.0% |  25/ 75 | MAYBE    |
| 118 | 23.0% |  23/ 77 | MAYBE    |
| 119 |  8.0% |   8/ 92 | MAYBE    |
| 120 |  5.0% |   5/ 95 | MAYBE    |
| 121 |  0.0% |   0/100 | TOXIC    |
| 122 |  0.0% |   0/100 | TOXIC    |
| 123 |  0.0% |   0/100 | TOXIC    |

---

## 0xb5 (181 decimal) Patterns

### Classification Summary

- **SAFE**: 7 lengths

- **MAYBE**: 14 lengths

- **TOXIC**: 10 lengths


### Detailed Results

| Length | Success Rate | Success/Fail | Classification |
|--------|--------------|--------------|----------------|
| 100 | 100.0% | 100/  0 | SAFE     |
| 101 | 100.0% | 100/  0 | SAFE     |
| 102 | 100.0% | 100/  0 | SAFE     |
| 103 | 100.0% | 100/  0 | SAFE     |
| 104 | 100.0% | 100/  0 | SAFE     |
| 105 | 100.0% | 100/  0 | SAFE     |
| 106 | 100.0% | 100/  0 | SAFE     |
| 107 | 98.0% |  98/  2 | MAYBE    |
| 108 | 96.0% |  96/  4 | MAYBE    |
| 109 | 90.0% |  90/ 10 | MAYBE    |
| 110 | 83.0% |  83/ 17 | MAYBE    |
| 111 | 75.0% |  75/ 25 | MAYBE    |
| 112 | 71.0% |  71/ 29 | MAYBE    |
| 113 | 54.0% |  54/ 46 | MAYBE    |
| 114 | 54.0% |  54/ 46 | MAYBE    |
| 115 | 46.0% |  46/ 54 | MAYBE    |
| 116 | 38.0% |  38/ 62 | MAYBE    |
| 117 | 28.0% |  28/ 72 | MAYBE    |
| 118 | 21.0% |  21/ 79 | MAYBE    |
| 119 | 12.0% |  12/ 88 | MAYBE    |
| 120 |  8.0% |   8/ 92 | MAYBE    |
| 121 |  0.0% |   0/100 | TOXIC    |
| 122 |  0.0% |   0/100 | TOXIC    |
| 123 |  0.0% |   0/100 | TOXIC    |
| 124 |  0.0% |   0/100 | TOXIC    |
| 125 |  0.0% |   0/100 | TOXIC    |
| 126 |  0.0% |   0/100 | TOXIC    |
| 127 |  0.0% |   0/100 | TOXIC    |
| 128 |  0.0% |   0/100 | TOXIC    |
| 129 |  0.0% |   0/100 | TOXIC    |
| 130 |  0.0% |   0/100 | TOXIC    |

**TOXIC LENGTHS:** 121-130 bytes (10 lengths)

**SAFE LENGTHS:** 100-106 bytes (7 lengths)

**INTERMITTENT LENGTHS:** 107-120 bytes (14 lengths)

**TRANSITION ZONE:** 106-121 bytes

### Transition Zone Details

| Length | Success Rate | Success/Fail | Classification |
|--------|--------------|--------------|----------------|
| 104 | 100.0% | 100/  0 | SAFE     |
| 105 | 100.0% | 100/  0 | SAFE     |
| 106 | 100.0% | 100/  0 | SAFE     |
| 107 | 98.0% |  98/  2 | MAYBE    |
| 108 | 96.0% |  96/  4 | MAYBE    |
| 109 | 90.0% |  90/ 10 | MAYBE    |
| 110 | 83.0% |  83/ 17 | MAYBE    |
| 111 | 75.0% |  75/ 25 | MAYBE    |
| 112 | 71.0% |  71/ 29 | MAYBE    |
| 113 | 54.0% |  54/ 46 | MAYBE    |
| 114 | 54.0% |  54/ 46 | MAYBE    |
| 115 | 46.0% |  46/ 54 | MAYBE    |
| 116 | 38.0% |  38/ 62 | MAYBE    |
| 117 | 28.0% |  28/ 72 | MAYBE    |
| 118 | 21.0% |  21/ 79 | MAYBE    |
| 119 | 12.0% |  12/ 88 | MAYBE    |
| 120 |  8.0% |   8/ 92 | MAYBE    |
| 121 |  0.0% |   0/100 | TOXIC    |
| 122 |  0.0% |   0/100 | TOXIC    |
| 123 |  0.0% |   0/100 | TOXIC    |

---
