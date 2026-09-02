# What API surface does a library's OWN TEST SUITE reach?

**The decision gate for P3.LIFT, measured before any generator was written.**

Our negative-capability work says jansson's widest single plan calls **3 of 83** exported
functions, the union over every valid base plan reaches **7**, and mutational synthesis
widened that to 43 (52%) while delivering **+0.40% coverage against OGHarn's +14%**. Widening
the candidate space by mutation is refuted. Unit tests were the remaining hypothesis, and the
question was whether they express anything a `setup -> consume -> destroy` plan cannot.

| library | exported | reached by tests | surface | sequences | widest single test |
|---|---|---|---|---|---|
| zstd | 66 | 65 | **98.5%** | 113 | 56 |
| jansson | 81 | 75 | **92.6%** | 71 | 21 |
| cjson | 78 | 71 | **91.0%** | 74 | 51 |
| expat | 67 | 61 | **91.0%** | 194 | 12 |
| libwebp | 30 | 20 | **66.7%** | 4 | 13 |
| libyaml | 48 | 30 | **62.5%** | 9 | 16 |
| lcms2 | 291 | 168 | **57.7%** | 248 | 18 |
| zlib | 81 | 42 | **51.9%** | 40 | 12 |
| libpng | 245 | 68 | **27.8%** | 23 | 16 |

**Median surface reached: 66.7%** across the 9 libraries with C tests.

## The comparison that decides it

For jansson, the one library measured every way:

| | functions reached | of 81-83 exports |
|---|---|---|
| our widest single plan | 3 | 3.6% |
| union over all valid base plans | 7 | 8% |
| union with mutational synthesis | 43 | 52% |
| **one test function (`test_chaos`)** | **21** | **26%** |
| **the test suite** | **75** | **92.6%** |

A SINGLE test function reaches seven times what our widest plan reaches. cjson has one test
calling 51 distinct APIs and zstd one calling 56; our plans call three or four. The tests
express orderings no header states -- which is exactly what killed synthesis on libyaml,
where every widened candidate aborted on a valid input because `yaml_parser_set_encoding`
asserts `!parser->encoding` and nothing in yaml.h says so.

**The hypothesis survives.** Building a generator on this is justified.

## Where it does not apply, recorded rather than omitted

jbig2dec, libde265, yajl reached nothing: they ship no C test files at all (brotli's tests are shell scripts
over testdata; jbig2dec and yajl test through their CLI). A test-lifting producer will
produce nothing for those libraries, and that is a real bound on the technique, not a bug.

libpng at 27.8% is the low end among libraries that DO have tests -- its 245 exports are
mostly setters its test programs never touch.

## Two extractor defects found while measuring, both of which understated the answer

**Test directories were only looked for at the ROOT.** expat keeps tests at
`expat/expat/tests`, lcms2 at `testbed/`, libpng under `contrib/`. Three of the first six
libraries reported 0% -- read as "the tests express nothing", meaning "the tool did not find
them".

**Tests are often declared by a MACRO, not as a C function.** expat uses the `check`
framework's `START_TEST(name)`; googletest uses `TEST(suite, name)`. Matching only plain
definitions reported expat at 0% from 18 files that plainly call `XML_ParserCreate`. With the
macro forms recognised it reaches 91.0% from 194 sequences.

Both are the same error: a zero from a measuring instrument is a claim about the instrument
until it is checked.
