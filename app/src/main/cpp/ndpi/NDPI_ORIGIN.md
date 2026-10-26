# nDPI

`src/` is a copy of `src/include` and `src/lib` of [nDPI](https://github.com/ntop/nDPI)
5.0 by ntop, licensed under the GNU Lesser General Public License v3.0 (see `COPYING`),
taken from PCAPdroid's nDPI fork at commit
[`40a1605bf7643488a3ac55ac2e2564dc8eaa6869`](https://github.com/emanuele-f/nDPI/commit/40a1605bf7643488a3ac55ac2e2564dc8eaa6869),
the version PCAPdroid ships on Android. It is unmodified; only `Makefile.in` and the
`ndpi_define.h.in` template were left out.

`generated/` holds the headers nDPI's `configure` script produces (`ndpi_config.h`,
`ndpi_define.h`), taken from PCAPdroid's `generated/nDPI` for the same commit.

`CMakeLists.txt` builds the slim variant PCAPdroid uses (no libinjection, roaring
bitmaps or filters).
